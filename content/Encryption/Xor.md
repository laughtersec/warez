---
publish: true
created: 2026-04-03T11:26:46.375+05:30
modified: 2026-04-03T13:08:11.454+05:30
published: 2026-04-03T13:08:11.454+05:30
tags:
  - payload-encryption
  - string-obscurement
---

Its a good choice because it doesn't require libraries and can be easily implemented, and is faster than [[RC4]] and [[AES]]. The same implementation can be used for encryption _and_ decryption.

The following implementation uses a single byte key

```c
VOID XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey)
{
	for(size_t i = 0; i < sShellcodeSize; i++)
	{
		pShellcode[i] = pShellcode[i] ^ bKey;
	}
}
```

Obviously if the key is only 1-byte long, it can be bruteforced. The following is a logic where the key used for every byte changes (initial\_key + index), thus making it much harder to bruteforce.

```c
VOID XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey)
{
	for(size_t i = 0; i < sShellcodeSize; i++)
	{
		pShellcode[i] = pShellcode[i] ^ (bKey + i);
	}
}
```

Best for obscuring strings.
