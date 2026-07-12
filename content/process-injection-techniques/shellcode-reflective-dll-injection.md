---
publish: true
created: 2026-04-04T13:29:18.078+05:30
tags:
  - reflective
---

## Observation

It is based on the same principle behind [[reflective-dll-injection]], except we are loading our own shellcode, which in itself acts as a loader for the DLL appended to our shellcode.

- We don't need to use `CreateFile` to read our DLL byte by byte from disk, because it is in-memory, appended to our loader's shellcode.
- The loader shellcode is an in-memory PE loader like in [[reflective-dll-injection]] (PE headers, sections, entry point) and executes functions exported by our DLL.
  The whole thing is just this huge shellcode that will be stored somewhere in the PE file, and we only need to execute it from somewhere.

## Working

[Here is an example](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-shellcode-dll-injection)

In the example, the shellcode is placed in the resource section. We can theoretically place it in any section, or can have it written anywhere in the memory of a process.

## Preliminaries

Lets try to understand what happened [here](https://github.com/monoxgas/sRDI/).

Looking at the python or powershell script that is responsible to convert the DLL to **shellcode**, we find that it arranges all the instructions in the following manner:

```python
return bootstrap + rdiShellcode + dllBytes + userData
```

Lets break down each part

- **bootstrap**: What it really does is setup locations of _rdishellcode_, _dllBytes_ and _userData_ so that it can be flawlessly referenced throughout the execution of the **shellcode**.
- **rdiShellcode**: These are the instructions which will reflectively load the DLL into the process like in [[reflective-dll-injection]].
- **dllBytes**: This is your DLL that you passed to the script and is stored byte by byte, which will be reflectively loaded by **rdiShellcode**.
- **userData**: This is optional, and by default is set to "None".
