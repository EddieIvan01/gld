# Go shellcode LoaDer


## Build

```
go build
```

## Usage

Generate shellcode by CS/MSF first, then generate the wrapped-shellcode-binary:

```
./gld shellcode.bin [x64/x86]
```

In default, gld will detect whether it's in a VM and whether there is any disassembly process.