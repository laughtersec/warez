---
publish: true
title: Classic Code Injection VirtualProtect
created: 2025-08-20T19:08:23.036+05:30
tags:
  - CreateToolhelp32Snapshot
  - OpenProcess
  - VirtualAllocEx
  - WriteProcessMemory
  - VirtualProtectEx
  - CreateRemoteThread
  - WaitForSingleObject
---

## Observation

This technique ==solves the issue of EDRs flagging RWX regions== in a process as suspicious, as seen in [classic-code-injection-local-process](process-injection-techniques/classic-code-injection-local-process.md) and  [rwx-hunting-and-injection](process-injection-techniques/rwx-hunting-and-injection.md). A memory region with RW permissions is first created, then its permissions are changed to RX using `VirtualProtect`.

## Working

- Find a process with necessary rights (such as `PROCESS_ALL_ACCESS`) using `CreateToolhelp32Snapshot`.
- Use `OpenProcess` function to get a handle to it.
- Allocate memory to its address space using `VirtualAllocEx`.
- Use `WriteProcessMemory` to write the shellcode into the allocated memory.
- Use `VirtualProtectEx` to change the RW permission to RX.
- Create a remote thread to execute the shellcode using `CreateRemoteThread`.
