package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	cliOnce sync.Once
	cliPath string
	cliErr  error
)

// buildCLI 编译一次命令行工具，供跨进程测试使用。
func buildCLI(t *testing.T) string {
	t.Helper()
	cliOnce.Do(func() {
		dir, err := os.MkdirTemp("", "envelope-cli-build")
		if err != nil {
			cliErr = err
			return
		}
		cliPath = filepath.Join(dir, "envelope-cli")
		cmd := exec.Command("go", "build", "-o", cliPath, "./cmd/envelope-cli")
		cmd.Env = append(os.Environ(), "GOCACHE="+os.Getenv("GOCACHE"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			cliErr = err
			cliPath = ""
			_ = out
		}
	})
	if cliErr != nil {
		t.Fatalf("build cli: %v", cliErr)
	}
	return cliPath
}

func runCLI(t *testing.T, bin, op string, key, ctx, input []byte) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(bin, op, "-key", hex.EncodeToString(key), "-ctx", string(ctx))
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Logf("cli stderr: %s", stderr.String())
	}
	return stdout.Bytes(), err
}

func TestCrossProcessRoundTrip(t *testing.T) {
	bin := buildCLI(t)
	key := testKey(t)
	ctx := []byte("deploy/config:v2")

	for _, n := range []int{0, 1, 4095, 4096, 4097, 1<<20 + 3} {
		plain := make([]byte, n)
		if _, err := rand.Read(plain); err != nil {
			t.Fatal(err)
		}

		// 库加密 -> 独立进程解密
		var ct bytes.Buffer
		if err := Encrypt(key, ctx, bytes.NewReader(plain), &ct, nil); err != nil {
			t.Fatal(err)
		}
		out, err := runCLI(t, bin, "decrypt", key, ctx, ct.Bytes())
		if err != nil {
			t.Fatalf("n=%d cli decrypt: %v", n, err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("n=%d lib->cli mismatch", n)
		}

		// 独立进程加密 -> 库解密
		ct2, err := runCLI(t, bin, "encrypt", key, ctx, plain)
		if err != nil {
			t.Fatalf("n=%d cli encrypt: %v", n, err)
		}
		var out2 bytes.Buffer
		if err := Decrypt(key, ctx, bytes.NewReader(ct2), &out2, nil); err != nil {
			t.Fatalf("n=%d lib decrypt: %v", n, err)
		}
		if !bytes.Equal(out2.Bytes(), plain) {
			t.Fatalf("n=%d cli->lib mismatch", n)
		}

		// 独立进程 -> 另一个独立进程
		out3, err := runCLI(t, bin, "decrypt", key, ctx, ct2)
		if err != nil {
			t.Fatalf("n=%d cli decrypt 2: %v", n, err)
		}
		if !bytes.Equal(out3, plain) {
			t.Fatalf("n=%d cli->cli mismatch", n)
		}
	}
}

func TestCrossProcessTamperFails(t *testing.T) {
	bin := buildCLI(t)
	key := testKey(t)
	ctx := []byte("ctx")
	plain := make([]byte, 100000)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	ct, err := runCLI(t, bin, "encrypt", key, ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xff
	out, err := runCLI(t, bin, "decrypt", key, ctx, ct)
	if err == nil {
		t.Fatal("cli decrypt of tampered ciphertext must fail")
	}
	if len(out) != 0 {
		t.Fatalf("cli emitted %d plaintext bytes on failure", len(out))
	}
}

// chunkedReader 以不固定分批大小交付数据，模拟不可回退流。
type chunkedReader struct {
	data   []byte
	off    int
	batch  int
	jitter []int
	i      int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := r.batch + r.jitter[r.i%len(r.jitter)]
	r.i++
	if n > len(p) {
		n = len(p)
	}
	if n > len(r.data)-r.off {
		n = len(r.data) - r.off
	}
	copy(p, r.data[r.off:r.off+n])
	r.off += n
	return n, nil
}

func TestBatchSizeVariation(t *testing.T) {
	key := testKey(t)
	ctx := []byte("ctx")
	plain := make([]byte, 200000)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	opts := &Options{ChunkSize: 4096}

	// 参考密文（一次性读入）。
	var ref bytes.Buffer
	if err := Encrypt(key, ctx, bytes.NewReader(plain), &ref, opts); err != nil {
		t.Fatal(err)
	}

	// 加密侧：不同分批大小下加密-解密往返必须逐字节还原。
	for _, batch := range []int{1, 7, 1024, 65536} {
		src := &chunkedReader{data: plain, batch: batch, jitter: []int{0, 3, 1}}
		var ct bytes.Buffer
		if err := Encrypt(key, ctx, src, &ct, opts); err != nil {
			t.Fatalf("batch %d encrypt: %v", batch, err)
		}
		var out bytes.Buffer
		if err := Decrypt(key, ctx, bytes.NewReader(ct.Bytes()), &out, opts); err != nil {
			t.Fatalf("batch %d decrypt: %v", batch, err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("batch %d mismatch", batch)
		}
	}

	// 解密侧：不同分批喂入同一密文，输出必须一致。
	ctBytes := ref.Bytes()
	for _, batch := range []int{1, 13, 4096, 100000} {
		src := &chunkedReader{data: ctBytes, batch: batch, jitter: []int{0, 5}}
		var out bytes.Buffer
		if err := Decrypt(key, ctx, src, &out, opts); err != nil {
			t.Fatalf("decrypt batch %d: %v", batch, err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("decrypt batch %d mismatch", batch)
		}
	}
}
