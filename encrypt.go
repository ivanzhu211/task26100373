package envelope

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// Encrypt 从 src 流式读取明文，加密后写入 dst。
// masterKey 必须为 32 字节；context 不参与明文但必须参与真实性保护。
func Encrypt(masterKey, context []byte, src io.Reader, dst io.Writer, opts *Options) error {
	if len(masterKey) != keyLen {
		return ErrInvalidKey
	}
	chunkSize := opts.chunkSize()
	if chunkSize < minChunkSize || chunkSize > maxChunkSize {
		return ErrInvalidOption
	}

	// 长度事先未知：先缓冲 smallMaxPlain+1 字节以选择模式。
	head := make([]byte, smallMaxPlain+1)
	n, err := io.ReadFull(src, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}
	if n <= smallMaxPlain {
		return encryptSmall(masterKey, context, head[:n], dst)
	}
	return encryptChunked(masterKey, context, src, dst, head[:n], chunkSize)
}

// encryptSmall 用主密钥直接加密（密钥由随机盐派生，单次使用）。
func encryptSmall(masterKey, context, plain []byte, dst io.Writer) error {
	salt, err := randBytes(saltLen)
	if err != nil {
		return err
	}
	key, err := deriveKey(masterKey, salt, "ENVE1/small")
	if err != nil {
		return err
	}
	g, err := newGCM(key)
	if err != nil {
		return err
	}
	hdr := &header{mode: modeSmall, salt: salt}
	hb, err := hdr.encode()
	if err != nil {
		return err
	}
	if err := writeAll(dst, hb); err != nil {
		return err
	}
	aad := smallAAD(context)
	return writeAll(dst, g.Seal(nil, zeroNonce, plain, aad))
}

// encryptChunked 用随机数据密钥分块加密正文，主密钥包裹数据密钥。
func encryptChunked(masterKey, context []byte, src io.Reader, dst io.Writer, first []byte, chunkSize int) error {
	dataKey, err := randBytes(keyLen)
	if err != nil {
		return err
	}
	wrapSalt, err := randBytes(saltLen)
	if err != nil {
		return err
	}
	wrapKey, err := deriveKey(masterKey, wrapSalt, "ENVE1/wrap")
	if err != nil {
		return err
	}
	wg, err := newGCM(wrapKey)
	if err != nil {
		return err
	}
	wrapped := wg.Seal(nil, zeroNonce, dataKey, wrapAAD(context))

	chunkKey, err := deriveKey(dataKey, nil, "ENVE1/chunk")
	if err != nil {
		return err
	}
	macKey, err := deriveKey(dataKey, nil, "ENVE1/mac")
	if err != nil {
		return err
	}
	cg, err := newGCM(chunkKey)
	if err != nil {
		return err
	}

	hdr := &header{mode: modeChunked, salt: wrapSalt, chunkSize: uint32(chunkSize), wrapped: wrapped}
	hb, err := hdr.encode()
	if err != nil {
		return err
	}
	if err := writeAll(dst, hb); err != nil {
		return err
	}
	headerHash := sha256.Sum256(hb)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(hb)

	// 已缓冲的 first 与其后的源流拼接为统一输入。
	combined := io.MultiReader(bytes.NewReader(first), src)
	buf := make([]byte, chunkSize)
	prevTag := make([]byte, gcmTagLen)
	var index, total uint64

	for {
		n, rerr := io.ReadFull(combined, buf)
		if rerr == io.EOF {
			break // 无剩余数据（总长恰为分块整数倍）
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			return rerr
		}
		chunk := buf[:n]
		var nonce [gcmNonceLen]byte
		binary.BigEndian.PutUint64(nonce[4:], index)
		ct := cg.Seal(nil, nonce[:], chunk, chunkAAD(context, headerHash, prevTag, index))
		if err := writeAll(dst, ct); err != nil {
			return err
		}
		tag := ct[len(ct)-gcmTagLen:]
		mac.Write(tag)
		prevTag = append(prevTag[:0], tag...)
		total += uint64(len(chunk))
		index++
		if rerr == io.ErrUnexpectedEOF {
			break // 短读即最后一块
		}
	}

	var tail [16]byte
	binary.BigEndian.PutUint64(tail[0:8], index)
	binary.BigEndian.PutUint64(tail[8:16], total)
	mac.Write(tail[:])
	return writeAll(dst, mac.Sum(nil))
}

func smallAAD(context []byte) []byte {
	return append([]byte("ENVE1|small|"), context...)
}

func wrapAAD(context []byte) []byte {
	return append([]byte("ENVE1|wrap|"), context...)
}

// chunkAAD 绑定上下文、头部、前一块 tag（链式）与块序号。
func chunkAAD(context []byte, headerHash [32]byte, prevTag []byte, index uint64) []byte {
	aad := make([]byte, 0, len("ENVE1|chunk|")+len(context)+32+16+8)
	aad = append(aad, "ENVE1|chunk|"...)
	aad = append(aad, context...)
	aad = append(aad, headerHash[:]...)
	aad = append(aad, prevTag...)
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index)
	return append(aad, idx[:]...)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
