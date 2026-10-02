// envelope-cli 是测试用的独立进程命令行工具，从标准输入读取、写到标准输出。
//
//	envelope-cli encrypt|decrypt -key <hex> | -keyfile <path> -ctx <string> [-chunksize n] [-tempdir dir]
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"envelope"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: envelope-cli encrypt|decrypt [flags]")
	}
	op := os.Args[1]
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	keyHex := fs.String("key", "", "master key as hex")
	keyFile := fs.String("keyfile", "", "file containing master key as hex")
	ctx := fs.String("ctx", "", "business context")
	chunkSize := fs.Int("chunksize", 0, "chunk size in bytes")
	tempDir := fs.String("tempdir", "", "temp dir for decryption spool")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	key, err := loadKey(*keyHex, *keyFile)
	if err != nil {
		fatal(err.Error())
	}
	opts := &envelope.Options{TempDir: *tempDir, ChunkSize: *chunkSize}

	switch op {
	case "encrypt":
		err = envelope.Encrypt(key, []byte(*ctx), os.Stdin, os.Stdout, opts)
	case "decrypt":
		err = envelope.Decrypt(key, []byte(*ctx), os.Stdin, os.Stdout, opts)
	default:
		fatal("unknown op: " + op)
	}
	if err != nil {
		fatal(err.Error())
	}
}

func loadKey(keyHex, keyFile string) ([]byte, error) {
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		keyHex = string(b)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("bad key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "envelope-cli:", msg)
	os.Exit(1)
}
