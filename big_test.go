package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// 2 GiB 完整性与资源测试。默认跳过，设置 ENVELOPE_BIGTEST=1 后运行：
//
//	ENVELOPE_BIGTEST=1 go test -run TestBig2GiB -v .
const bigSize = int64(2) << 30 // 2 GiB

// prngReader 用 splitmix64 生成确定性的伪随机明文流（不可回退）。
type prngReader struct {
	state uint64
	left  int64
	buf   []byte
	off   int
}

func newPRNGReader(seed uint64, size int64) *prngReader {
	return &prngReader{state: seed, left: size, buf: make([]byte, 1<<20)}
}

func (r *prngReader) refill() {
	for i := 0; i < len(r.buf); i += 8 {
		r.state += 0x9e3779b97f4a7c15
		z := r.state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z = z ^ (z >> 31)
		binary.LittleEndian.PutUint64(r.buf[i:], z)
	}
}

func (r *prngReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	if r.off == len(r.buf) {
		r.refill()
		r.off = 0
	}
	n := copy(p, r.buf[r.off:])
	if int64(n) > r.left {
		n = int(r.left)
	}
	r.off += n
	r.left -= int64(n)
	return n, nil
}

// noSeek 隐藏底层 Reader 的 Seek 能力，模拟不可回退流。
type noSeek struct{ r io.Reader }

func (s noSeek) Read(p []byte) (int, error) { return s.r.Read(p) }

func maxRSSBytes(t *testing.T, cmd *exec.Cmd) int64 {
	t.Helper()
	ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok {
		t.Skip("rusage unavailable")
	}
	if runtime.GOOS == "darwin" {
		return ru.Maxrss // 字节
	}
	return ru.Maxrss * 1024 // Linux: KiB
}

func TestBig2GiB(t *testing.T) {
	if os.Getenv("ENVELOPE_BIGTEST") == "" {
		t.Skip("set ENVELOPE_BIGTEST=1 to run the 2 GiB test")
	}
	bin := buildCLI(t)
	key := testKey(t)
	keyHex := hex.EncodeToString(key)
	ctx := "archive/2gib"
	dir := t.TempDir()
	ctPath := filepath.Join(dir, "archive.env")
	spoolDir := filepath.Join(dir, "spool")
	if err := os.Mkdir(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 基线内存：处理极小输入的子进程峰值 RSS。
	baseline := rssOf(t, bin, keyHex, ctx, bytes.NewReader(nil), io.Discard, "", "encrypt")
	t.Logf("baseline child max RSS: %.1f MiB", float64(baseline)/(1<<20))

	// 期望明文哈希：生成器确定性，可独立复算。
	expectHash := sha256.New()
	if _, err := io.Copy(expectHash, newPRNGReader(42, bigSize)); err != nil {
		t.Fatal(err)
	}
	expect := expectHash.Sum(nil)

	// 加密：不可回退输入流 -> 密文文件。
	ctFile, err := os.Create(ctPath)
	if err != nil {
		t.Fatal(err)
	}
	encCmd := exec.Command(bin, "encrypt", "-key", keyHex, "-ctx", ctx)
	encCmd.Stdin = noSeek{newPRNGReader(42, bigSize)}
	encCmd.Stdout = ctFile
	encErr := &bytes.Buffer{}
	encCmd.Stderr = encErr
	if err := encCmd.Run(); err != nil {
		t.Fatalf("encrypt: %v (%s)", err, encErr.String())
	}
	ctFile.Close()
	encRSS := maxRSSBytes(t, encCmd)
	t.Logf("encrypt child max RSS: %.1f MiB (extra %.1f MiB)",
		float64(encRSS)/(1<<20), float64(encRSS-baseline)/(1<<20))
	if extra := encRSS - baseline; extra > 32<<20 {
		t.Fatalf("encrypt extra memory %d bytes exceeds 32 MiB", extra)
	}

	// 解密：不可回退输入流 -> 哈希校验，峰值内存受限。
	gotHash := sha256.New()
	ctIn, err := os.Open(ctPath)
	if err != nil {
		t.Fatal(err)
	}
	decCmd := exec.Command(bin, "decrypt", "-key", keyHex, "-ctx", ctx, "-tempdir", spoolDir)
	decCmd.Stdin = noSeek{ctIn}
	decCmd.Stdout = gotHash
	decErr := &bytes.Buffer{}
	decCmd.Stderr = decErr
	if err := decCmd.Run(); err != nil {
		t.Fatalf("decrypt: %v (%s)", err, decErr.String())
	}
	ctIn.Close()
	decRSS := maxRSSBytes(t, decCmd)
	t.Logf("decrypt child max RSS: %.1f MiB (extra %.1f MiB)",
		float64(decRSS)/(1<<20), float64(decRSS-baseline)/(1<<20))
	if extra := decRSS - baseline; extra > 32<<20 {
		t.Fatalf("decrypt extra memory %d bytes exceeds 32 MiB", extra)
	}
	if !bytes.Equal(gotHash.Sum(nil), expect) {
		t.Fatal("2 GiB round trip hash mismatch")
	}

	// 临时目录必须已清空（暂存文件被删除）。
	leftovers, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("spool dir not cleaned: %d entries", len(leftovers))
	}

	// 末尾损坏：解密必须失败且标准输出为零字节。
	corruptLastByte(t, ctPath)
	ctIn2, err := os.Open(ctPath)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	badCmd := exec.Command(bin, "decrypt", "-key", keyHex, "-ctx", ctx, "-tempdir", spoolDir)
	badCmd.Stdin = noSeek{ctIn2}
	badCmd.Stdout = &out
	err = badCmd.Run()
	ctIn2.Close()
	if err == nil {
		t.Fatal("decrypt of corrupted ciphertext must fail")
	}
	if out.Len() != 0 {
		t.Fatalf("corrupted input leaked %d plaintext bytes", out.Len())
	}
}

// rssOf 运行一次 CLI 并返回其子进程峰值 RSS。
func rssOf(t *testing.T, bin, keyHex, ctx string, in io.Reader, out io.Writer, tempDir, op string) int64 {
	t.Helper()
	args := []string{op, "-key", keyHex, "-ctx", ctx}
	if tempDir != "" {
		args = append(args, "-tempdir", tempDir)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatalf("baseline %s: %v", op, err)
	}
	return maxRSSBytes(t, cmd)
}

func corruptLastByte(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{0}
	if _, err := f.ReadAt(b, st.Size()-1); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b, st.Size()-1); err != nil {
		t.Fatal(err)
	}
}

// TestBigSpoolContainsNoPlaintext 验证解密暂存文件不承载明文。
// 使用库内钩子在第一遍验证完成后扫描暂存文件。
func TestBigSpoolContainsNoPlaintext(t *testing.T) {
	if os.Getenv("ENVELOPE_BIGTEST") == "" {
		t.Skip("set ENVELOPE_BIGTEST=1 to run the 2 GiB test")
	}
	key := testKey(t)
	ctx := []byte("spool-check")

	// 采样明文块（生成器确定性，可复算任意偏移）。
	const sampleLen = 64 << 10
	samples := map[int64][]byte{}
	for _, off := range []int64{0, bigSize / 3, bigSize / 2, bigSize - sampleLen - 1} {
		samples[off] = readPlainAt(t, off, sampleLen)
	}

	// 加密到临时文件。
	dir := t.TempDir()
	ctPath := filepath.Join(dir, "ct")
	ctFile, err := os.Create(ctPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(key, ctx, noSeek{newPRNGReader(42, bigSize)}, ctFile, nil); err != nil {
		t.Fatal(err)
	}
	ctFile.Close()

	// 解密，钩子在暂存完成后扫描临时文件。
	spoolDir := filepath.Join(dir, "spool")
	if err := os.Mkdir(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	scanned := false
	afterSpoolHook = func(f *os.File) {
		scanned = true
		st, err := f.Stat()
		if err != nil {
			t.Errorf("stat spool: %v", err)
			return
		}
		wantSize := bigSize + int64((bigSize+defaultChunkSize-1)/defaultChunkSize)*gcmTagLen
		if st.Size() != wantSize {
			t.Errorf("spool size %d, want %d", st.Size(), wantSize)
		}
		// 流式滑窗扫描，避免把暂存文件整体读入内存。
		if off := findAnySubsequence(f, samples); off >= 0 {
			t.Errorf("spool contains plaintext block from offset %d", off)
		}
	}
	defer func() { afterSpoolHook = nil }()

	ctIn, err := os.Open(ctPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ctIn.Close()
	gotHash := sha256.New()
	if err := Decrypt(key, ctx, noSeek{ctIn}, gotHash, &Options{TempDir: spoolDir}); err != nil {
		t.Fatal(err)
	}
	if !scanned {
		t.Fatal("spool hook was not called")
	}
}

// findAnySubsequence 在 r 中查找任一样本，返回首个命中样本的偏移或 -1。
// 使用带重叠的滑窗，内存占用有界。
func findAnySubsequence(r io.Reader, samples map[int64][]byte) int64 {
	const window = 8 << 20
	maxSample := 0
	for _, s := range samples {
		if len(s) > maxSample {
			maxSample = len(s)
		}
	}
	buf := make([]byte, 0, window+maxSample)
	tmp := make([]byte, window)
	for {
		n, err := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		for off, sample := range samples {
			if bytes.Contains(buf, sample) {
				return off
			}
		}
		if err == io.EOF {
			return -1
		}
		if err != nil {
			return -1
		}
		// 保留尾部 maxSample-1 字节作为重叠。
		keep := maxSample - 1
		if len(buf) > keep {
			buf = append([]byte(nil), buf[len(buf)-keep:]...)
		}
	}
}

// readPlainAt 复算生成器在指定偏移处的明文。
func readPlainAt(t *testing.T, off, n int64) []byte {
	t.Helper()
	r := newPRNGReader(42, off+n)
	if _, err := io.CopyN(io.Discard, r, off); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}
