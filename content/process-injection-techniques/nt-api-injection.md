---
publish: true
created: 2025-09-20T10:37:54.502+05:30
tags:
  - EnumProcess
  - OpenProcess
  - GetModuleFileNameEx
  - GetProcAddress
  - NtOpenProcess
  - NtAllocateVirtualMemory
  - NtWriteVirtualMemory
  - NtCreateThreadEx
---

## Observation

- Defines some necessary structures and typedefs for NT API calls, like so

```c
<...>
#pragma comment(lib, "ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _LSA_UNICODE_STRING { USHORT Length;	USHORT MaximumLength; PWSTR  Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI* NtOpenProcess_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );

typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(WINAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(WINAPI* NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

void InitializeObjectAttributes(
	POBJECT_ATTRIBUTES pObjectAttributes,
	PUNICODE_STRING pObjectName,
	ULONG Attributes,
	HANDLE RootDirectory,
	PVOID SecurityDescriptor
) {
	pObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
	pObjectAttributes->RootDirectory = RootDirectory;
	pObjectAttributes->ObjectName = pObjectName;
	pObjectAttributes->Attributes = Attributes;
	pObjectAttributes->SecurityDescriptor = SecurityDescriptor;
	pObjectAttributes->SecurityQualityOfService = NULL;
}
<...>
```

## Working

- Search for remote process by name and retrieve PID using `EnumProcesses`, `OpenProcess`, and `GetModuleFileNameEx`
- NT API functions are not directly available through typical Windows headers, so the program dynamically loads them using `GetProcAddress`.
- Use `NtOpenProcess` to open the target process.
- Allocate memory in the target process using `NtAllocateVirtualMemory` with RWX permissions.
- Write the shellcode to the allocated memory using `NtWriteVirtualMemory`.
- Finally, create a thread using `NtCreateThreadEx`.
