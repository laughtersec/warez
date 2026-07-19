---
publish: true
title: Classic Code Injection Local Process
created: 2025-08-20T17:16:00.921+05:30
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
