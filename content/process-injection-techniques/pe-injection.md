---
publish: true
title: PE Injection
created: 2025-09-06T01:10:46.521+05:30
tags:
  - OpenProcess
  - GetModuleHandle
  - VirtualAlloc
  - VirtualAllocEx
  - WriteProcessMemory
  - CreateRemoteThread
---

## Observation

## Working

- Open target process using `OpenProcess`.
- Get current image's base address using `GetModuleHandle(NULL)`.
- Allocate memory for the local image using `VirtualAlloc`.
- Allocate memory in the target process using `VirtualAllocEx`.
- Calculate the difference between the target and local base addresses (delta) and relocate the image.
- Write the relocated image into the target process using `WriteProcessMemory`.
- Start the injected PE using `CreateRemoteThread`.
