---
publish: true
created: 2025-09-06T20:48:20.965+05:30
tags:
  - CreateToolhelp32Snapshot
  - Process32First
  - Process32Next
  - OpenProcess
  - VirtualAllocEx
  - WriteProcessMemory
  - Thread32First
  - Thread32Next
  - OpenThread
  - QueueUserAPC
  - SleepEx
  - WaitForSingleObjectEx
  - WaitForMultipleObjectEx
---

## Observation

## Working

- Find a target process using `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`.
- Open a handle to the target process using `OpenProcess`.
- Allocate memory in the target process for the shellcode using `VirtualAllocEx`.
- Write the shellcode into the allocated memory in the target process using `WriteProcessMemory`.
- Find a thread ID within the target process using `CreateToolhelp32Snapshot`, `Thread32First`,`Thread32Next`.
- Use `OpenThread` to open the thread that was found in the target process, to inject the APC.
- Queue the APC to the target thread using `QueueUserAPC`.
- Call `Sleep`, so that a later `SleepEx`

## Notes

- User Mode APC (Asynchronous Procedure Calls): Data structures that encapsulate a function to be called in usermode at IRQL `PASSIVE_LEVEL` when the thread goes into an alertable state.  The alertable state is typically accomplished by calling `SleepEx`,`WaitForSingleObjectEx`,`WaitForMultipleObjectEx` and similar APIs.
