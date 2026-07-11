---
publish: true
created: 2025-10-02T11:51:34.745+05:30
modified: 2025-10-17T17:29:32.894+05:30
published: 2025-10-17T17:29:32.894+05:30
tags:
  - EnumProcess
  - OpenProcess
  - non-volatile-register-retrieval
  - CONTAINING_RECORD
  - GetProcAddressKernel32
  - Deobfuscation
  - VirtualAllocEx
  - WriteProcessMemory
  - CreateRemoteThread
---

## Observations

This is the combination of [[PEB Walk Injection]] and [[Classic Code Injection With API Obfuscation]]. The names of the functions we need are obfuscated before getting a pointer to them via PEB walking.

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

- Using this pointer, traverse the PEB's linked list of loaded modules to find the base address of the desired module using  `CONTAINING_RECORD(lEntry, ...)`, then iterate through the list of loaded modules in the process, and obtain its base address.
- Using the base address, retrieve the pointer to its functions using `GetProcAddressKernel32` (after deobfuscation)
- Run your shellcode using pointer to `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` (after deobfuscation).
