---
publish: true
created: 2026-04-04T13:29:18.078+05:30
modified: 2026-04-04T15:37:39.441+05:30
published: 2026-04-04T15:37:39.441+05:30
tags:
  - reflective
---

## Observation

It is based on the same principle behind [[Reflective DLL Injection]], except we are loading our own shellcode, which in itself acts as a loader for the DLL appended to our shellcode.

- We don't need to use `CreateFile` to read our DLL byte by byte from disk, because it is in-memory, appended to our loader's shellcode.
- The loader shellcode is an in-memory PE loader like in [[Reflective DLL Injection]] (PE headers, sections, entry point) and executes functions exported by our DLL.

## Working

[Here is an example](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-shellcode-dll-injection)

In the example, the shellcode is placed in the resource section. We can theoretically place it in any section.
