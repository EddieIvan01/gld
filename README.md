# Go shellcode LoaDer

## Usage

Generate shellcode via CS/MSF first, then use gld to compile wrapped-binary:

```
./gld shellcode.bin [x64/x86]
```

## Tech

### Loader

+ Shellcode is encrypted via AES-GCM, it will be decrypted and loaded in runtime
+ Use `ntdll!ZwProtectVirtualMemory` instead of `kernelbase!VirtualProtect` (bypass possible hooks) to bypass DEP 
+ Use local variable instead of string literal to pass procedure name (`string([]byte{...})`), to avoid static memory matching

### Detector

+ VM
  + Check if has a blacklist MAC prefixes
  + Check if physics memory < 2GB or number of CPU cores < 2 (cpuid and `GlobalMemoryStatusEx`)
+ DBG
  + Check if there is a debugger process (`CreateToolhelp32Snapshot`)
  + Check if current process is being debugged by a user-mode debugger (`IsDebuggerPresent`)