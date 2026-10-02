package envelope

import (
	"bytes"
	"crypto/rand"
	"testing"
)

const chunkedHeaderLen = magicLen + versionLen + modeLen + saltLen + 4 + keyLen + gcmTagLen

// encryptWith 用固定密钥加密，便于构造多份密文。
func encryptWith(t *testing.T, key, ctx, plain []byte, chunkSize int) []byte {
	t.Helper()
	var ct bytes.Buffer
	opts := &Options{ChunkSize: chunkSize}
	if err := Encrypt(key, ctx, bytes.NewReader(plain), &ct, opts); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ct.Bytes()
}

// mustFail 要求解密失败且输出为零字节。
func mustFail(t *testing.T, key, ctx, ct []byte, what string) {
	t.Helper()
	var out bytes.Buffer
	err := Decrypt(key, ctx, bytes.NewReader(ct), &out, nil)
	if err == nil {
		t.Fatalf("%s: expected failure, got success", what)
	}
	if out.Len() != 0 {
		t.Fatalf("%s: expected zero plaintext output, got %d bytes", what, out.Len())
	}
}

func chunkedBody(t *testing.T, key, ctx []byte, chunkSize int) (ct []byte, nChunks int) {
	t.Helper()
	// 必须超过 4096 字节以进入分块模式：18 个整块 + 100 字节尾块。
	plain := make([]byte, chunkSize*18+100)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	ct = encryptWith(t, key, ctx, plain, chunkSize)
	nChunks = 19
	wantLen := chunkedHeaderLen + 18*(chunkSize+gcmTagLen) + 100 + gcmTagLen + macLen
	if len(ct) != wantLen {
		t.Fatalf("unexpected ciphertext length %d, want %d", len(ct), wantLen)
	}
	return ct, nChunks
}

func chunkAt(ct []byte, chunkSize, i int) []byte {
	off := chunkedHeaderLen + i*(chunkSize+gcmTagLen)
	return ct[off : off+chunkSize+gcmTagLen]
}

func TestTamperBitFlip(t *testing.T) {
	key, ctx := testKey(t), []byte("ctx")
	ct, _ := chunkedBody(t, key, ctx, 256)
	for _, pos := range []int{0, 5, chunkedHeaderLen - 1, chunkedHeaderLen, chunkedHeaderLen + 100, len(ct) - macLen - 1, len(ct) - 1} {
		bad := bytes.Clone(ct)
		bad[pos] ^= 0x01
		mustFail(t, key, ctx, bad, "bit flip")
	}
}

func TestTamperTruncateAndAppend(t *testing.T) {
	key, ctx := testKey(t), []byte("ctx")
	ct, _ := chunkedBody(t, key, ctx, 256)
	for _, n := range []int{1, 16, macLen, macLen + 50, len(ct) / 2} {
		mustFail(t, key, ctx, ct[:len(ct)-n], "truncate")
	}
	mustFail(t, key, ctx, append(bytes.Clone(ct), 0x00), "append 1 byte")
	mustFail(t, key, ctx, append(bytes.Clone(ct), ct[:64]...), "append header bytes")
}

func TestTamperWrongContextAndKey(t *testing.T) {
	key, ctx := testKey(t), []byte("ctx")
	ct, _ := chunkedBody(t, key, ctx, 256)
	mustFail(t, key, []byte("other"), ct, "wrong context")
	mustFail(t, key, nil, ct, "nil context")
	otherKey := testKey(t)
	mustFail(t, otherKey, ctx, ct, "wrong key")
}

func TestTamperChunkReorderDuplicateDelete(t *testing.T) {
	key, ctx := testKey(t), []byte("ctx")
	chunkSize := 256
	ct, _ := chunkedBody(t, key, ctx, chunkSize)
	hdr := ct[:chunkedHeaderLen]
	c0 := chunkAt(ct, chunkSize, 0)
	c1 := chunkAt(ct, chunkSize, 1)
	c2 := chunkAt(ct, chunkSize, 2)
	rest := ct[chunkedHeaderLen+3*(chunkSize+gcmTagLen):]

	build := func(parts ...[]byte) []byte {
		return bytes.Join(parts, nil)
	}
	mustFail(t, key, ctx, build(hdr, c1, c0, c2, rest), "swap chunks 0/1")
	mustFail(t, key, ctx, build(hdr, c0, c0, c1, c2, rest), "duplicate chunk 0")
	mustFail(t, key, ctx, build(hdr, c0, c2, rest), "delete chunk 1")
	mustFail(t, key, ctx, build(hdr, c2, c1, c0, rest), "reverse chunks")
}

func TestTamperCrossCiphertextSplice(t *testing.T) {
	// 相同主密钥与上下文的两份密文，互换中间分块必须被拒绝。
	key, ctx := testKey(t), []byte("ctx")
	chunkSize := 256
	ctA, _ := chunkedBody(t, key, ctx, chunkSize)
	ctB, _ := chunkedBody(t, key, ctx, chunkSize)

	spliced := bytes.Clone(ctA)
	copy(spliced[chunkedHeaderLen+chunkSize+gcmTagLen:], chunkAt(ctB, chunkSize, 1))
	mustFail(t, key, ctx, spliced, "splice middle chunk from other ciphertext")

	// 互换被包裹的数据密钥必须被拒绝。
	swapWrapped := bytes.Clone(ctA)
	copy(swapWrapped[chunkedHeaderLen-keyLen-gcmTagLen:chunkedHeaderLen],
		ctB[chunkedHeaderLen-keyLen-gcmTagLen:chunkedHeaderLen])
	mustFail(t, key, ctx, swapWrapped, "swap wrapped data key")

	// 互换尾部认证码必须被拒绝。
	tail := bytes.Clone(ctA)
	copy(tail[len(tail)-macLen:], ctB[len(ctB)-macLen:])
	mustFail(t, key, ctx, tail, "swap trailer")
}

func TestTamperModeByte(t *testing.T) {
	key, ctx := testKey(t), []byte("ctx")
	small := encryptWith(t, key, ctx, []byte("tiny"), 0)
	bad := bytes.Clone(small)
	bad[magicLen+versionLen] = modeChunked
	mustFail(t, key, ctx, bad, "mode small->chunked")

	ct, _ := chunkedBody(t, key, ctx, 256)
	bad2 := bytes.Clone(ct)
	bad2[magicLen+versionLen] = modeSmall
	mustFail(t, key, ctx, bad2, "mode chunked->small")
}

func TestSourceReadFailure(t *testing.T) {
	key, ctx := testKey(t), []byte("ctx")
	ct, _ := chunkedBody(t, key, ctx, 256)
	// 源流在中途失败：不允许交付任何明文。
	r := &failAfterReader{data: ct, n: chunkedHeaderLen + 300}
	var out bytes.Buffer
	if err := Decrypt(key, ctx, r, &out, nil); err == nil {
		t.Fatal("expected error from failing source")
	}
	if out.Len() != 0 {
		t.Fatalf("expected zero output, got %d", out.Len())
	}
}

type failAfterReader struct {
	data []byte
	n    int
	off  int
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.off >= r.n {
		return 0, errBoom
	}
	remain := r.n - r.off
	if len(p) > remain {
		p = p[:remain]
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

var errBoom = errorString("boom")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestTamperHugeChunkSizeHeader(t *testing.T) {
	key, ctx := testKey(t), []byte("ctx")
	ct, _ := chunkedBody(t, key, ctx, 256)
	bad := bytes.Clone(ct)
	// chunkSize 字段位于 magic+version+mode+salt 之后。
	off := magicLen + versionLen + modeLen + saltLen
	bad[off], bad[off+1], bad[off+2], bad[off+3] = 0xff, 0xff, 0xff, 0xff
	mustFail(t, key, ctx, bad, "huge chunk size")
}
