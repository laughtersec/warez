---
publish: true
created: 2025-09-06T17:36:42.081+05:30
modified: 2026-03-06T19:32:20.912+05:30
published: 2026-03-06T19:32:20.912+05:30
tags:
  - NtQueryInformationProcess
  - NtReadVirtualMemory
  - WriteProcessMemory
  - NtResumeThread
---

## Observation

- typedefs were created for native functions `NtReadVirtualMemory`,`NtResumeThread`,`NtQueryInformationProcess`.
- Using these typedefs, pointers to the Native functions directly from `ntdll.dll` using `GetProcAddress(GetModuleHandle(ntdll.dll), "function_name");` are stored after casting them with their respective `NTAPI*` type.

## Working

- Get PEB address and pointer to image base address using `NtQueryInformationProcess`, from the returned process information structure.
- Get process image base address using `NtReadVirtualMemory` (`&iBase`).
- Use it with `NtReadVirtualMemory` to read target process image headers (`hBuffer`).
- Address of entry point can be calculated with this information.

```c
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hBuffer;
PIMAGE_NT_HEADER64 ntHeader = (PIMAGE_NT_HEADER64)((DWORD_PTR)hBuffer + dosHeader->e_lfanew);
LPVOID cEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)iBase);
```

- Write shellcode to image entry point using `WriteProcessMemory` in `cEntry`.
- Execute it using `NtResumeThread`.
