---
publish: true
created: 2025-08-20T16:01:57.394+05:30
modified: 2025-08-20T19:51:21.778+05:30
published: 2025-08-20T19:51:21.778+05:30
tags:
  - NtGetNextProcess
  - GetProcessImageFileName
  - VirtualQueryEx
  - WriteProcessMemory
  - CreateRemoteThread
  - WaitForSingleObject
---

## Observation

This is a subset technique derived from [[Classic Code Injection Local Process]] and, except we don't allocate a buffer with rwx permissions on our own process, but rather look for processes with those permissions and inject our shellcode into it.

## Working

- `NtGetNextProcess` is used to enumerate all processes.
- `GetProcessImageFileName` to retrieve the image name of the process.
- `VirtualQueryEx` is used to query for memory regions marked as `PAGE_EXECUTE_READWRITE`.
- Once the right process is found, `WriteProcessMemory` is used to write the shellcode into the memory region of said process.
- A thread on that process is created using `CreateRemoteThread`.
