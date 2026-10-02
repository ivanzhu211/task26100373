package envelope

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, keyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func roundTrip(t *testing.T, plain, ctx []byte, opts *Options) []byte {
	t.Helper()
	key := testKey(t)
	var ct bytes.Buffer
	if err := Encrypt(key, ctx, bytes.NewReader(plain), &ct, opts); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	var out bytes.Buffer
	if err := Decrypt(key, ctx, bytes.NewReader(ct.Bytes()), &out, opts); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	return out.Bytes()
}

func TestRoundTripSizes(t *testing.T) {
	sizes := []int{0, 1, 100, 4095, 4096, 4097, 8192, 1 << 20, 3<<20 + 7}
	for _, n := range sizes {
		plain := make([]byte, n)
		if _, err := rand.Read(plain); err != nil {
			t.Fatal(err)
		}
		got := roundTrip(t, plain, []byte("ctx"), nil)
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: round trip mismatch", n)
		}
	}
}

func TestRoundTripSmallChunkSize(t *testing.T) {
	// 小分块 + 各种分批输入，结果必须一致。
	plain := make([]byte, 100000)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	opts := &Options{ChunkSize: 1024}
	got := roundTrip(t, plain, []byte("ctx"), opts)
	if !bytes.Equal(got, plain) {
		t.Fatal("round trip mismatch with small chunks")
	}
}

func TestEmptyPlaintextAuthenticated(t *testing.T) {
	key := testKey(t)
	var ct bytes.Buffer
	if err := Encrypt(key, []byte("ctx"), bytes.NewReader(nil), &ct, nil); err != nil {
		t.Fatal(err)
	}
	if ct.Len() == 0 {
		t.Fatal("empty plaintext must still produce authenticated ciphertext")
	}
	// 篡改一字节必须失败。
	b := ct.Bytes()
	b[len(b)-1] ^= 0xff
	var out bytes.Buffer
	if err := Decrypt(key, []byte("ctx"), bytes.NewReader(b), &out, nil); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
	if out.Len() != 0 {
		t.Fatal("no plaintext may be emitted on failure")
	}
}
