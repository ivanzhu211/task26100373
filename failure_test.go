package enveil

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// flakyReader fails with errAfter after delivering n bytes.
type flakyReader struct {
	r        io.Reader
	n        int
	errAfter error
}

func (f *flakyReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, f.errAfter
	}
	if len(p) > f.n {
		p = p[:f.n]
	}
	n, err := f.r.Read(p)
	f.n -= n
	return n, err
}

var errBoom = errors.New("boom")

func TestSourceReadFailureYieldsZeroPlaintext(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	ct := encryptToBytes(t, pattern(2*chunkSize+5), key, ctx)

	// Fail the source at several points, including near the end.
	for _, failAt := range []int{0, fixedLen, len(ct) / 2, len(ct) - 2} {
		dst := &countingWriter{}
		src := &flakyReader{r: bytes.NewReader(ct), n: failAt, errAfter: errBoom}
		err := Decrypt(dst, src, key, ctx, WithTempDir(t.TempDir()))
		if err == nil {
			t.Fatalf("failAt %d: expected error", failAt)
		}
		if dst.n != 0 {
			t.Fatalf("failAt %d: destination received %d bytes", failAt, dst.n)
		}
	}
}

func TestEncryptSourceReadFailure(t *testing.T) {
	key := testKey()
	src := &flakyReader{r: bytes.NewReader(pattern(100000)), n: 5000, errAfter: errBoom}
	var ct bytes.Buffer
	if err := Encrypt(&ct, src, key, nil); !errors.Is(err, errBoom) {
		t.Fatalf("expected source error, got %v", err)
	}
}

func TestSpoolFilesCleanedUp(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	ct := encryptToBytes(t, pattern(5000), key, ctx)
	bad := append([]byte{}, ct...)
	bad[len(bad)-1] ^= 0xff

	dir := t.TempDir()
	// Success and failure both must remove the spool.
	if _, err := decryptToBytes(t, ct, key, ctx); err != nil {
		t.Fatal(err)
	}
	dst := &countingWriter{}
	if err := Decrypt(dst, bytes.NewReader(bad), key, ctx, WithTempDir(dir)); err == nil {
		t.Fatal("expected auth failure")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("spool files left behind: %v", names)
	}
}

func TestSpoolContainsOnlyCiphertext(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	// Distinctive plaintext that must never hit the disk.
	marker := bytes.Repeat([]byte("TOP-SECRET-MARKER-0123456789"), 100)
	pt := append(append([]byte{}, marker...), pattern(chunkSize)...)
	ct := encryptToBytes(t, pt, key, ctx)

	dir := t.TempDir()
	// Hook: scan the spool directory while decryption is in progress by
	// using a slow destination and polling from another goroutine is
	// overkill here; instead decrypt and then verify no file in dir
	// ever persists, plus directly inspect spool behavior via a
	// mid-decryption snapshot using a blocking writer.
	snapshot := make(chan []byte, 8)
	release := make(chan struct{})
	w := &pausingWriter{onFirstWrite: func() {
		// Decryption is now in pass 2; the spool file exists.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("readdir: %v", err)
		}
		for _, e := range entries {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Errorf("read spool: %v", err)
				continue
			}
			snapshot <- data
		}
		close(snapshot)
		<-release
	}}
	done := make(chan error, 1)
	go func() {
		done <- Decrypt(w, bytes.NewReader(ct), key, ctx, WithTempDir(dir))
	}()
	seen := 0
	for data := range snapshot {
		seen++
		if bytes.Contains(data, marker) {
			t.Error("spool file contains plaintext marker")
		}
	}
	close(release)
	err := <-done
	if err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatal("no spool file observed during decryption")
	}
}

// pausingWriter blocks on the first Write until released, letting the
// test inspect the spool mid-decryption.
type pausingWriter struct {
	onFirstWrite func()
	called       bool
}

func (w *pausingWriter) Write(p []byte) (int, error) {
	if !w.called {
		w.called = true
		w.onFirstWrite()
	}
	return len(p), nil
}
