---
publish: true
title: NtCreateSection and NtMapViewOfSection
created: 2025-08-20T20:29:27.094+05:30
tags:
  - NtCreateSection
  - NtMapViewOfSection
  - OpenProcess
  - memcpy
  - CreateRemoteThread
---

## Observation

- Need to properly understand properly how `NtMapViewOfSection` works. Because the PoC writes shellcode to the local process' mapped view with RW permissions, but creates a thread on a target process with a mapped view with RX permissions (to which nothing is explicitly written). I need to investigate how writing a shellcode in a locally mapped view affects a mapped view on a remote process. Creating a thread only makes sense when there is executable permissions. Perhaps this is some kind of "shared pool" mechanism.

## Working

- Create a new memory section with RWX permissions using `NtCreateSection`.
- Map a view of the section into the local process with RW permissions using `NtMapViewOfSection`.
- Get a handle to the target process using `OpenProcess`.
- Map a view of the section into the target process with RX permissions using `NtMapViewOfSection`.
- Copy the shellcode to local process' view mapped by us using `memcpy`. This will reflect in the target process' view
- Create a remote thread in the target process using `CreateRemoteThread` to execute the shellcode.
