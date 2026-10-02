package enveil

import (
	"bytes"
	"io"
	"testing"
)

// countingWriter records how many bytes it received.
type countingWriter struct {
	n int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	return len(p), nil
}

// splitCiphertext splits ct into the encoded header and the raw chunk
// records, using the library's own framing.
func splitCiphertext(t *testing.T, ct []byte) (headerBytes []byte, records [][]byte) {
	t.Helper()
	_, n, err := func() (header, int, error) {
		h, hb, err := readHeader(bytes.NewReader(ct))
		return h, len(hb), err
	}()
	if err != nil {
		t.Fatalf("splitCiphertext header: %v", err)
	}
	headerBytes = ct[:n]
	r := bytes.NewReader(ct[n:])
	buf := make([]byte, lenSize+maxRecordLen)
	for {
		rec, err := readRecord(r, buf)
		if err == io.EOF {
			return headerBytes, records
		}
		if err != nil {
			t.Fatalf("splitCiphertext record: %v", err)
		}
		cp := make([]byte, len(rec))
		copy(cp, rec)
		records = append(records, cp)
	}
}

// expectReject decrypts ct and requires an error and zero plaintext
// bytes delivered to the destination.
func expectReject(t *testing.T, what string, ct []byte, key, context []byte) {
	t.Helper()
	dst := &countingWriter{}
	err := Decrypt(dst, bytes.NewReader(ct), key, context, WithTempDir(t.TempDir()))
	if err == nil {
		t.Fatalf("%s: tampered ciphertext accepted", what)
	}
	if dst.n != 0 {
		t.Fatalf("%s: destination received %d plaintext bytes on failure", what, dst.n)
	}
}

func tamperSuite(t *testing.T, size int) {
	t.Helper()
	key := testKey()
	ctx := []byte("tenant-42/archive")
	pt := pattern(size)
	ct := encryptToBytes(t, pt, key, ctx)

	// Sanity: the untampered ciphertext decrypts.
	if _, err := decryptToBytes(t, ct, key, ctx); err != nil {
		t.Fatalf("baseline decrypt: %v", err)
	}

	// Truncations: head, middle, and just the last byte.
	for _, n := range []int{1, len(ct) / 2, len(ct) - 1} {
		expectReject(t, "truncate", ct[:n], key, ctx)
	}
	// Append one byte and append a whole valid-looking record.
	expectReject(t, "append-byte", append(append([]byte{}, ct...), 0x00), key, ctx)
	_, recs := splitCiphertext(t, ct)
	appended := append(append([]byte{}, ct...), recs[len(recs)-1]...)
	expectReject(t, "append-record", appended, key, ctx)

	// Single-bit corruptions across the whole ciphertext.
	for _, pos := range []int{0, magicLen, magicLen + 1, len(ct) / 3, len(ct) / 2, len(ct) - 5, len(ct) - 1} {
		bad := append([]byte{}, ct...)
		bad[pos] ^= 0x01
		expectReject(t, "bitflip", bad, key, ctx)
	}

	// Mode byte flip.
	bad := append([]byte{}, ct...)
	bad[magicLen] ^= 0x01
	expectReject(t, "mode-flip", bad, key, ctx)
}

func TestTamperDirectMode(t *testing.T) {
	tamperSuite(t, 100)  // small direct
	tamperSuite(t, 0)    // empty direct
	tamperSuite(t, 4096) // largest direct
}

func TestTamperEnvelopeMode(t *testing.T) {
	tamperSuite(t, 4097)            // smallest envelope
	tamperSuite(t, 2*chunkSize+999) // multi-chunk envelope
}

func TestEnvelopeHeaderTamper(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	ct := encryptToBytes(t, pattern(5000), key, ctx)

	// Corrupt the wrapped data key and its nonce.
	for _, pos := range []int{fixedLen, fixedLen + wrapNonceLen, maxLen - 1} {
		bad := append([]byte{}, ct...)
		bad[pos] ^= 0x40
		expectReject(t, "wrapped-key-tamper", bad, key, ctx)
	}
}

func TestChunkStreamAttacks(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	pt := pattern(3*chunkSize + 777)
	ct := encryptToBytes(t, pt, key, ctx)
	hdr, recs := splitCiphertext(t, ct)
	if len(recs) != 4 { // 3 full chunks + 777-byte final chunk
		t.Fatalf("expected 4 records, got %d", len(recs))
	}
	join := func(parts ...[]byte) []byte {
		return bytes.Join(parts, nil)
	}

	// Reorder two chunks.
	expectReject(t, "reorder", join(hdr, recs[1], recs[0], recs[2], recs[3]), key, ctx)
	// Drop a middle chunk.
	expectReject(t, "drop", join(hdr, recs[0], recs[2], recs[3]), key, ctx)
	// Duplicate a chunk.
	expectReject(t, "duplicate", join(hdr, recs[0], recs[0], recs[1], recs[2], recs[3]), key, ctx)
	// Move the final chunk earlier.
	expectReject(t, "final-early", join(hdr, recs[0], recs[3], recs[1], recs[2]), key, ctx)
	// Strip the final chunk and remark a normal chunk as final.
	remarked := append([]byte{}, recs[2]...)
	remarked[lenSize] |= flagFinal
	expectReject(t, "fake-final", join(hdr, recs[0], recs[1], remarked), key, ctx)
}

func TestCrossCiphertextSplice(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	// Two ciphertexts under the same key and context.
	ctA := encryptToBytes(t, pattern(2*chunkSize+100), key, ctx)
	ctB := encryptToBytes(t, pattern(2*chunkSize+200), key, ctx)
	hdrA, recsA := splitCiphertext(t, ctA)
	hdrB, recsB := splitCiphertext(t, ctB)
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	// Header of A with body of B.
	expectReject(t, "headerA+bodyB", join(hdrA, recsB[0], recsB[1], recsB[2]), key, ctx)
	// Body of A with one chunk replaced from B.
	expectReject(t, "chunk-from-B", join(hdrA, recsA[0], recsB[1], recsA[2]), key, ctx)
	// Interleave chunks of A and B.
	expectReject(t, "interleave", join(hdrA, recsA[0], recsB[0], recsA[1], recsB[1], recsA[2]), key, ctx)
	// Whole body of B after header of A, keeping B's final chunk.
	expectReject(t, "body-swap", join(hdrA, bytes.Join(recsB, nil)), key, ctx)
	_ = hdrB
}

func TestDirectModeSplice(t *testing.T) {
	key := testKey()
	ctx := []byte("ctx")
	ctA := encryptToBytes(t, pattern(100), key, ctx)
	ctB := encryptToBytes(t, pattern(200), key, ctx)
	hdrA, recsA := splitCiphertext(t, ctA)
	_, recsB := splitCiphertext(t, ctB)
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	expectReject(t, "direct-chunk-from-B", join(hdrA, recsB[0]), key, ctx)
	expectReject(t, "direct-extra-record", join(hdrA, recsA[0], recsA[0]), key, ctx)
}
