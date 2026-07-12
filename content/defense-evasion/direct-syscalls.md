---
publish: true
created: 2025-08-20T11:09:46.137+05:30
tags:
  - CreateToolhelp32Snapshot
  - NtOpenProcess
  - NtAllocateVirtualMemory
  - NtWriteVirtualMemory
  - NtCreateThreadEx
---

## Pre-requisites

Need an assembly file that makes syscalls to Win32 API functions directly, instead of going through `ntdll.dll`.

[SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) helps generate the assembly file.

## Working

After generating the assembly file,

- Search for a process by name and retrieve its Process ID (PID)
- Allocate RWX region into remote process using direct syscall.
- Write Shellcode into allocated memory using direct syscall.
- Execute the shellcode using direct syscall.
