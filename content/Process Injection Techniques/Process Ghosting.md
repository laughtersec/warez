---
publish: true
created: 2025-08-19T22:02:54.155+05:30
modified: 2025-08-20T15:21:21.782+05:30
published: 2025-08-20T15:21:21.782+05:30
tags:
  - CreateFile
  - GetFileSize
  - VirtualAlloc
  - ReadFile
  - NtOpenFile
  - NtSetInformationFile
  - WriteFile
  - NtCreateSection
  - NtCreateProcessEx
---

## Working

- Using `function` , load the malicious executable into memory.
- Mark the file for deletion using `function`.
- Launch the process from section by calling `function`.
- Calculate the entry point address.
- Execute the process in memory using a remote thread.
