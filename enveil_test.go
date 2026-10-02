package enveil

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// testKey returns a deterministic 256-bit master key.
func testKey() []byte {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// pattern returns a deterministic pseudo-random byte stream of n bytes.
func pattern(n int) []byte {
	buf := make([]byte, n)
	seed := byte(0x5a)
	for i := range buf {
		seed = seed*166 + 101 // LCG, low byte
		buf[i] = seed ^ byte(i>>8)
	}
	return buf
}

// batchedReader yields the underlying stream in varying batch sizes.
type batchedReader struct {
	r     io.Reader
	sizes []int
	i     int
}

func (b *batchedReader) Read(p []byte) (int, error) {
	n := b.sizes[b.i%len(b.sizes)]
	b.i++
	if n > len(p) {
		n = len(p)
	}
	return b.r.Read(p[:n])
}

func encryptToBytes(t *testing.T, plaintext, key, context []byte, batchSizes ...int) []byte {
	t.Helper()
	var src io.Reader = bytes.NewReader(plaintext)
	if len(batchSizes) > 0 {
		src = &batchedReader{r: src, sizes: batchSizes}
	}
	var ct bytes.Buffer
	if err := Encrypt(&ct, src, key, context); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ct.Bytes()
}

func decryptToBytes(t *testing.T, ct, key, context []byte, batchSizes ...int) ([]byte, error) {
	t.Helper()
	var src io.Reader = bytes.NewReader(ct)
	if len(batchSizes) > 0 {
		src = &batchedReader{r: src, sizes: batchSizes}
	}
	var pt bytes.Buffer
	err := Decrypt(&pt, src, key, context, WithTempDir(t.TempDir()))
	return pt.Bytes(), err
}

func TestRoundtripBoundaries(t *testing.T) {
	key := testKey()
	ctx := []byte("billing/config")
	for _, size := range []int{0, 1, 4095, 4096, 4097, 8192, 1<<20 + 3} {
		pt := pattern(size)
		ct := encryptToBytes(t, pt, key, ctx)
		got, err := decryptToBytes(t, ct, key, ctx)
		if err != nil {
			t.Fatalf("size %d: Decrypt: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: plaintext mismatch", size)
		}
	}
}

func TestEmptyPlaintextIsAuthenticated(t *testing.T) {
	key := testKey()
	ct := encryptToBytes(t, nil, key, []byte("ctx"))
	if len(ct) == 0 {
		t.Fatal("empty plaintext must still produce authenticated ciphertext")
	}
	got, err := decryptToBytes(t, ct, key, []byte("ctx"))
	if err != nil || len(got) != 0 {
		t.Fatalf("empty roundtrip: got %d bytes, err %v", len(got), err)
	}
	// Tampering with the only chunk must fail.
	ct[len(ct)-1] ^= 0xff
	if _, err := decryptToBytes(t, ct, key, []byte("ctx")); err == nil {
		t.Fatal("tampered empty-message ciphertext accepted")
	}
}

func TestBatchSizeInvariance(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	pt := pattern(3*chunkSize + 12345)
	ct := encryptToBytes(t, pt, key, ctx, 1, 7, 4096, 65536)
	for _, sizes := range [][]int{nil, {1}, {13, 1 << 20, 5}, {maxRecordLen}} {
		got, err := decryptToBytes(t, ct, key, ctx, sizes...)
		if err != nil {
			t.Fatalf("sizes %v: %v", sizes, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("sizes %v: mismatch", sizes)
		}
	}
}

func TestRandomizedCiphertext(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	pt := pattern(100)
	ct1 := encryptToBytes(t, pt, key, ctx)
	ct2 := encryptToBytes(t, pt, key, ctx)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("same plaintext encrypted twice produced identical ciphertext")
	}
}

func TestWrongKeyAndContext(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	for _, size := range []int{100, 4097, 2 << 20} {
		ct := encryptToBytes(t, pattern(size), key, ctx)

		badKey := testKey()
		badKey[0] ^= 1
		if got, err := decryptToBytes(t, ct, badKey, ctx); err == nil || len(got) != 0 {
			t.Fatalf("size %d: wrong key accepted (%d bytes out)", size, len(got))
		}
		if got, err := decryptToBytes(t, ct, key, []byte("other")); err == nil || len(got) != 0 {
			t.Fatalf("size %d: wrong context accepted (%d bytes out)", size, len(got))
		}
		if got, err := decryptToBytes(t, ct, key, nil); err == nil || len(got) != 0 {
			t.Fatalf("size %d: nil context accepted (%d bytes out)", size, len(got))
		}
	}
}

func TestKeySizeValidation(t *testing.T) {
	if err := Encrypt(io.Discard, bytes.NewReader(nil), make([]byte, 16), nil); err != ErrKeySize {
		t.Fatalf("Encrypt with 16-byte key: %v", err)
	}
	if err := Decrypt(io.Discard, bytes.NewReader(nil), make([]byte, 31), nil); err != ErrKeySize {
		t.Fatalf("Decrypt with 31-byte key: %v", err)
	}
}

func TestRandomKeySmoke(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	pt := pattern(5000)
	ct := encryptToBytes(t, pt, key, []byte("ctx"))
	got, err := decryptToBytes(t, ct, key, []byte("ctx"))
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("roundtrip failed: %v", err)
	}
}
