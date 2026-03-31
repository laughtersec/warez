---
publish: true
created: 2025-08-20T17:16:00.921+05:30
modified: 2025-08-20T17:19:08.098+05:30
published: 2025-08-20T17:19:08.098+05:30
tags:
  - VirtualAlloc
  - memcpy
  - CreateThread
  - WaitForSingleObject
---

## Working

- Allocate memory for payload with RWX permissions using `VirtualAlloc`.
- Copy shellcode to allocated buffer using `memcpy`.
- Run the shellcode by creating a threading using `CreateThread`.
