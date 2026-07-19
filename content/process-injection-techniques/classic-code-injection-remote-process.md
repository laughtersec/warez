---
publish: true
title: Classic Code Injection Remote Process
created: 2025-08-20T17:29:05.002+05:30
tags:
  - CreateToolhelp32Snapshot
  - OpenProcess
  - VirtualAllocEx
  - WriteProcessMemory
  - CreateRemoteThread
  - WaitForSingleObject
---

## Working

- Find a process with necessary rights (such as `PROCESS_ALL_ACCESS`) using `CreateToolhelp32Snapshot`.
- Use `OpenProcess` function to get a handle to it.
- Allocate memory to its address space using `VirtualAllocEx`.
- Use `WriteProcessMemory` to write the shellcode into the allocated memory.
- Create a remote thread to execute the shellcode using `CreateRemoteThread`.
