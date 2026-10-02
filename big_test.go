package enveil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// bigSize is the 2 GiB payload used by the resource test.
const bigSize = int64(2) << 30

// bigMemLimit is the allowed peak extra working memory beyond the Go
// runtime baseline, per the requirements (32 MiB).
const bigMemLimit = int64(32) << 20

// patternStream is a reproducible xorshift64* byte stream.
type patternStream struct {
	state uint64
	left  int64
	tail  [8]byte
	ntail int
}

func newPatternStream(seed uint64, n int64) *patternStream {
	return &patternStream{state: seed, left: n}
}

func (p *patternStream) Read(buf []byte) (int, error) {
	if p.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(buf))
	if n > p.left {
		n = p.left
	}
	i := int64(0)
	if p.ntail > 0 {
		i += int64(copy(buf[i:n], p.tail[8-p.ntail:]))
		p.ntail -= int(i)
	}
	var word [8]byte
	for i < n {
		p.state ^= p.state >> 12
		p.state ^= p.state << 25
		p.state ^= p.state >> 27
		binary.LittleEndian.PutUint64(word[:], p.state*2685821657736338717)
		copied := copy(buf[i:n], word[:])
		i += int64(copied)
		if copied < 8 {
			copy(p.tail[:], word[:])
			p.ntail = 8 - copied
		}
	}
	p.left -= n
	return int(n), nil
}

// patternChecker verifies a stream against the expected pattern.
type patternChecker struct {
	expect *patternStream
	total  int64
}

func (c *patternChecker) Write(buf []byte) (int, error) {
	want := make([]byte, len(buf))
	if _, err := io.ReadFull(c.expect, want); err != nil {
		return 0, fmt.Errorf("pattern underrun: %w", err)
	}
	if !bytes.Equal(buf, want) {
		return 0, fmt.Errorf("plaintext mismatch at offset %d", c.total)
	}
	c.total += int64(len(buf))
	return len(buf), nil
}

// nonSeekable hides any Seek/Len methods of the wrapped reader.
type nonSeekable struct{ io.Reader }

// TestBigHelper is re-executed as a child process by TestBig2GiB.
func TestBigHelper(t *testing.T) {
	if os.Getenv("ENVEIL_BIG_HELPER") == "" {
		t.Skip("helper process")
	}
	mode := os.Getenv("ENVEIL_BIG_HELPER")
	key := testKey()
	ctx := []byte("big/archive")
	dir := os.Getenv("ENVEIL_DIR")
	ctPath := filepath.Join(dir, "big.ct")

	switch mode {
	case "baseline":
		// Small roundtrip through the same code paths: establishes the
		// Go runtime memory baseline.
		var ct bytes.Buffer
		src := newPatternStream(7, 1<<20)
		if err := Encrypt(&ct, src, key, ctx, WithTempDir(dir)); err != nil {
			fatal(err)
		}
		if err := Decrypt(io.Discard, &ct, key, ctx, WithTempDir(dir)); err != nil {
			fatal(err)
		}
	case "encrypt":
		ct, err := os.Create(ctPath)
		if err != nil {
			fatal(err)
		}
		src := nonSeekable{newPatternStream(7, bigSize)}
		if err := Encrypt(ct, src, key, ctx, WithTempDir(dir)); err != nil {
			fatal(err)
		}
		if err := ct.Close(); err != nil {
			fatal(err)
		}
	case "decrypt":
		ct, err := os.Open(ctPath)
		if err != nil {
			fatal(err)
		}
		defer ct.Close()
		checker := &patternChecker{expect: newPatternStream(7, bigSize)}
		if err := Decrypt(checker, nonSeekable{ct}, key, ctx, WithTempDir(dir)); err != nil {
			fatal(err)
		}
		if checker.total != bigSize {
			fatal(fmt.Errorf("got %d plaintext bytes, want %d", checker.total, bigSize))
		}
	case "decrypt-corrupt":
		ct, err := os.Open(ctPath)
		if err != nil {
			fatal(err)
		}
		defer ct.Close()
		delivered := int64(0)
		w := writerFunc(func(p []byte) (int, error) {
			delivered += int64(len(p))
			return len(p), nil
		})
		err = Decrypt(w, nonSeekable{ct}, key, ctx, WithTempDir(dir))
		if err == nil {
			fatal(fmt.Errorf("corrupted ciphertext accepted"))
		}
		if delivered != 0 {
			fatal(fmt.Errorf("delivered %d plaintext bytes before failure", delivered))
		}
		fmt.Println("zero-plaintext-on-corruption confirmed")
	default:
		fatal(fmt.Errorf("unknown helper mode %q", mode))
	}
	os.Exit(0)
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "helper:", err)
	os.Exit(1)
}

// runBigHelper runs the helper as a subprocess and returns its peak RSS
// in bytes.
func runBigHelper(t *testing.T, mode, dir string) (int64, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^TestBigHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "ENVEIL_BIG_HELPER="+mode, "ENVEIL_DIR="+dir)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	rusage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok {
		t.Fatalf("no rusage available")
	}
	if err != nil {
		t.Fatalf("helper %s failed: %v\n%s", mode, err, out.String())
	}
	// On darwin ru_maxrss is in bytes; on Linux it is in kilobytes.
	maxrss := rusage.Maxrss
	if maxrss < 1<<20 { // implausibly small for bytes: must be KB
		maxrss *= 1024
	}
	return maxrss, out.String()
}

// TestBig2GiB is the reproducible 2 GiB integrity and resource test.
// Run with: ENVEIL_BIG=1 go test -run TestBig2GiB -v
func TestBig2GiB(t *testing.T) {
	if os.Getenv("ENVEIL_BIG") != "1" {
		t.Skip("set ENVEIL_BIG=1 to run the 2 GiB resource test")
	}
	dir := t.TempDir()
	ctPath := filepath.Join(dir, "big.ct")

	baselineRSS, _ := runBigHelper(t, "baseline", dir)
	t.Logf("baseline peak RSS: %.1f MiB", float64(baselineRSS)/(1<<20))

	// Encrypt 2 GiB from a non-seekable source.
	encRSS, _ := runBigHelper(t, "encrypt", dir)
	t.Logf("encrypt peak RSS: %.1f MiB (delta %.1f MiB)",
		float64(encRSS)/(1<<20), float64(encRSS-baselineRSS)/(1<<20))
	if delta := encRSS - baselineRSS; delta > bigMemLimit {
		t.Fatalf("encrypt peak extra memory %d bytes exceeds 32 MiB", delta)
	}
	st, err := os.Stat(ctPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() < bigSize {
		t.Fatalf("ciphertext too small: %d", st.Size())
	}
	t.Logf("ciphertext size: %d bytes (overhead %d)", st.Size(), st.Size()-bigSize)

	// Decrypt and verify the full 2 GiB roundtrip.
	decRSS, _ := runBigHelper(t, "decrypt", dir)
	t.Logf("decrypt peak RSS: %.1f MiB (delta %.1f MiB)",
		float64(decRSS)/(1<<20), float64(decRSS-baselineRSS)/(1<<20))
	if delta := decRSS - baselineRSS; delta > bigMemLimit {
		t.Fatalf("decrypt peak extra memory %d bytes exceeds 32 MiB", delta)
	}

	// Corrupt the final byte: decryption must fail with zero plaintext.
	f, err := os.OpenFile(ctPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(-1, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], st.Size()-1); err != nil {
		t.Fatal(err)
	}
	last[0] ^= 0xff
	if _, err := f.WriteAt(last[:], st.Size()-1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cmd := exec.Command(os.Args[0], "-test.run", "^TestBigHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "ENVEIL_BIG_HELPER=decrypt-corrupt", "ENVEIL_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("corruption-rejection helper failed:\n%s", out)
	}
	if !bytes.Contains(out, []byte("zero-plaintext-on-corruption confirmed")) {
		t.Fatalf("expected zero-plaintext confirmation, got:\n%s", out)
	}
	t.Log("tail corruption rejected with zero plaintext delivered")

	// No spool files may remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "big.ct" {
			t.Fatalf("unexpected leftover file: %s", e.Name())
		}
	}
}

// TestBigSpoolNoPlaintext scans the live spool file during a large
// decryption for any 64-byte window of the plaintext pattern.
func TestBigSpoolNoPlaintext(t *testing.T) {
	if os.Getenv("ENVEIL_BIG") != "1" {
		t.Skip("set ENVEIL_BIG=1 to run the 2 GiB resource test")
	}
	dir := t.TempDir()
	key := testKey()
	ctx := []byte("big/archive")

	// Build a 256 MiB ciphertext (enough for the scan to catch the
	// spool mid-decryption without excessive runtime).
	const size = int64(256) << 20
	ctPath := filepath.Join(dir, "scan.ct")
	ctFile, err := os.Create(ctPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(ctFile, nonSeekable{newPatternStream(9, size)}, key, ctx); err != nil {
		t.Fatal(err)
	}
	ctFile.Close()

	ct, err := os.Open(ctPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ct.Close()

	// On the first plaintext write, the spool holds verified ciphertext;
	// scan it fully for any plaintext window.
	scanned := make(chan int64, 1)
	release := make(chan struct{})
	w := writerFunc(func(p []byte) (int, error) {
		select {
		case <-release:
			return len(p), nil
		default:
		}
		var total int64
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.Name() == "scan.ct" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			total += int64(len(data))
			if containsPatternWindow(data, 9) {
				t.Error("spool file contains a plaintext window")
			}
		}
		scanned <- total
		<-release
		return len(p), nil
	})
	done := make(chan error, 1)
	go func() {
		done <- Decrypt(w, nonSeekable{ct}, key, ctx, WithTempDir(dir))
	}()
	spooled := <-scanned
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	t.Logf("scanned %d bytes of live spool: no plaintext found", spooled)
	if spooled == 0 {
		t.Fatal("no spool content observed")
	}
}

// containsPatternWindow reports whether data contains any 64-byte
// window of the pattern stream with the given seed. It checks windows
// at every 64-byte-aligned offset of the pattern.
func containsPatternWindow(data []byte, seed uint64) bool {
	if len(data) < 64 {
		return false
	}
	// Generate the pattern in 64-byte windows and search for each.
	// To keep this cheap, sample every 4096th window.
	src := newPatternStream(seed, int64(len(data)))
	var window [64]byte
	for i := 0; ; i++ {
		if _, err := io.ReadFull(src, window[:]); err != nil {
			return false
		}
		if i%4096 == 0 && bytes.Contains(data, window[:]) {
			return true
		}
	}
}
