# Go shellcode LoaDer

## Usage

Generate shellcode by CS/MSF first, then use gld to compile wrapped-shellcode-binary:

```
./gld shellcode.bin [x64/x86]
```

## Tech

### Loader

+ Change page's protect attribute to RWX then execute (`VirtualProtect`  and syscall)
+ Dynamic loading DLL and target procedure (`LoadLibrary/GetProcAddress`)
+ Don't use string literal and use random procedure name, to avoid static memory matching

### Detector

+ VM
  + Check if has a blacklist MAC prefixes
  + Check if physics memory < 2GB or number of CPU cores < 2 (cpuid and `GlobalMemoryStatusEx`)
+ DBG
  + Check if there is a debugger process (`CreateToolhelp32Snapshot`)
  + Check if current process is being debugged by a user-mode debugger (`IsDebuggerPresent`)