---
publish: true
title: Remote Thread Hijacking
created: 2025-09-06T15:26:02.229+05:30
tags:
  - EnumProcess
  - OpenProcess
  - GetModuleFileNameEx
  - VirtualAllocEx
  - WriteProcessMemory
  - CreateToolhelp32Snapshot
  - Thread32First
  - Thread32Next
  - OpenThread
  - SuspendThread
  - GetCurrentThreadContext
  - SetThreadContext
  - ResumeThread
---

## Observation

## Working

- Identify a target process and thread.
- Suspend the target thread.
- Get that thread's context (registers etc.)
- Allocate memory in the target process using \`\`.
- Write payload into the allocated
