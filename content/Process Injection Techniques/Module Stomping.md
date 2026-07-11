---
publish: true
created: 2025-10-17T17:36:13.787+05:30
modified: 2025-10-19T21:27:49.768+05:30
published: 2025-10-19T21:27:49.768+05:30
tags:
  - EnumProcess
  - OpenProcess
  - GetModuleFileNameEx
  - VirtualAllocEx
  - WriteProcessMemory
  - GetProcAddress
  - CreateRemoteThread
  - FindModuleBase
---

## Observation

Parts of a legitimate module are modified with malicious code and then the target process is forced to load it.

## Working

- Retrieve target process ID using `EnumProcess` and get a handle to it using `OpenProcess`.
- Find the base address of loaded module in the target process to "stomp" using `EnumProcessModules` and `GetModuleFileNameEx`.
- Allocating memory in the target process using `VirtualAllocEx`.
- Writing DLL Path to the allocated memory in target process using `WriteProcessMemory`.
- Get address of LoadLibraryA and converting it to the thread routine using `GetProcAddress`.
- Creating remote thread to load target DLL using `CreateRemoteThread`.
- Finding the base address of the loaded DLL using `FindModuleBase`, then calculating entry point in memory = `dllEntryPoint + moduleBaseAddress`.
- Over-write the DLL's entry point with the shellcode using `WriteProcessMemory`.
- Execute the shellcode from inside the benign DLL using `CreateRemoteThread`.
