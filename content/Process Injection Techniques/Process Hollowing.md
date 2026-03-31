---
publish: true
created: 2025-08-19T18:15:08.115+05:30
modified: 2025-08-20T11:58:27.589+05:30
published: 2025-08-20T11:58:27.589+05:30
tags:
  - CreateProcess
  - ReadProcessMemory
  - NtUnmapViewOfSection
  - CreateFile
  - VirtualAllocEx
  - WriteProcessMemory
  - SetThreadContext
  - ResumeThread
---

## Working

- Create a legitimate process in suspended state.
- Retrieve thread context of this process.
- Unmap sections of the target process.
- Inject a malicious PE file from disk and over-write the sections of this process' memory.
- Relocate if the base address of the injected PE file differs from the suspended process.
- Set new entry-point using thread context.
