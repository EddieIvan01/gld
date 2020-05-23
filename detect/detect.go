package detect

import (
	"net"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/klauspost/cpuid"
	"github.com/shirou/gopsutil/mem"
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

func checkResource() bool {
	if cpuid.CPU.VM() {
		return true
	}

	vmStat, err := mem.VirtualMemory()

	if err != nil {
		return false
	}
	if runtime.NumCPU() < 2 && vmStat.Total < 3072000000 {
		return true
	}

	return false
}

var blacklistDBG = []string{
	"IDA",
	"OLLYDBG",
	"WINDBG",
	"GHIDRA",
}

func detectDBG() bool {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}

	pe32 := syscall.ProcessEntry32{}
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = syscall.Process32First(handle, &pe32)

	for err == nil {
		exeFile := strings.ToUpper(syscall.UTF16ToString(pe32.ExeFile[:260]))
		for _, pn := range blacklistDBG {
			if strings.Contains(exeFile, pn) {
				return true
			}
		}
		err = syscall.Process32Next(handle, &pe32)
	}

	return false
}
