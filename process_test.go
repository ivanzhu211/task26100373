package enveil

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCrossProcessDecrypt encrypts in this process and decrypts in a
// freshly spawned independent process (the test binary re-executed as a
// helper), proving ciphertext is self-contained.
func TestCrossProcessDecrypt(t *testing.T) {
	if os.Getenv("ENVEIL_HELPER") == "decrypt" {
		helperDecrypt(t)
		return
	}

	key := testKey()
	ctx := []byte("deploy/region-7")
	for _, size := range []int{0, 4095, 4096, 4097, 1<<20 + 11} {
		pt := pattern(size)
		ct := encryptToBytes(t, pt, key, ctx)

		dir := t.TempDir()
		ctPath := filepath.Join(dir, "msg.ct")
		outPath := filepath.Join(dir, "msg.pt")
		if err := os.WriteFile(ctPath, ct, 0o600); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(os.Args[0], "-test.run", "^TestCrossProcessDecrypt$")
		cmd.Env = append(os.Environ(),
			"ENVEIL_HELPER=decrypt",
			"ENVEIL_KEY="+hex.EncodeToString(key),
			"ENVEIL_CTX="+string(ctx),
			"ENVEIL_CT="+ctPath,
			"ENVEIL_OUT="+outPath,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("size %d: helper failed: %v\n%s", size, err, out)
		}
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: cross-process plaintext mismatch", size)
		}
	}
}

// helperDecrypt runs in the child process: read ciphertext from a file,
// decrypt with key and context from the environment, write plaintext.
func helperDecrypt(t *testing.T) {
	key, err := hex.DecodeString(os.Getenv("ENVEIL_KEY"))
	if err != nil {
		t.Fatalf("helper key: %v", err)
	}
	ctPath := os.Getenv("ENVEIL_CT")
	outPath := os.Getenv("ENVEIL_OUT")

	ct, err := os.Open(ctPath)
	if err != nil {
		t.Fatalf("helper open: %v", err)
	}
	defer ct.Close()
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("helper create: %v", err)
	}
	if err := Decrypt(out, ct, key, []byte(os.Getenv("ENVEIL_CTX")), WithTempDir(filepath.Dir(outPath))); err != nil {
		t.Fatalf("helper decrypt: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("helper close: %v", err)
	}
	os.Exit(0)
}
