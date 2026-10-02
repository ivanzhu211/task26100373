package envelope

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
)

// afterSpoolHook 若非 nil，在解密第一遍（验证+暂存）完成后、
// 输出明文前被调用，参数为已归位的临时文件。仅供测试使用。
var afterSpoolHook func(f *os.File)

// Decrypt 从 src 流式读取密文，完整验证通过后才向 dst 写入明文。
// 验证失败或源读取失败时，dst 不会收到任何字节。
func Decrypt(masterKey, context []byte, src io.Reader, dst io.Writer, opts *Options) error {
	if len(masterKey) != keyLen {
		return ErrInvalidKey
	}
	hdr, rawHeader, err := decodeHeader(src)
	if err != nil {
		return err
	}
	if hdr.mode == modeSmall {
		return decryptSmall(masterKey, context, hdr, src, dst)
	}
	return decryptChunked(masterKey, context, hdr, rawHeader, src, dst, opts)
}

// decryptSmall 整体读入有界密文并一次性验证。
func decryptSmall(masterKey, context []byte, hdr *header, src io.Reader, dst io.Writer) error {
	maxCT := smallMaxPlain + gcmTagLen
	ct, err := io.ReadAll(io.LimitReader(src, int64(maxCT)+1))
	if err != nil {
		return err
	}
	if len(ct) > maxCT || len(ct) < gcmTagLen {
		return ErrFormat
	}
	key, err := deriveKey(masterKey, hdr.salt, "ENVE1/small")
	if err != nil {
		return err
	}
	g, err := newGCM(key)
	if err != nil {
		return err
	}
	plain, err := g.Open(nil, zeroNonce, ct, smallAAD(context))
	if err != nil {
		return ErrAuth
	}
	return writeAll(dst, plain)
}

// decryptChunked 第一遍：逐块验证并暂存密文；第二遍：从临时文件解密输出。
func decryptChunked(masterKey, context []byte, hdr *header, rawHeader []byte, src io.Reader, dst io.Writer, opts *Options) error {
	wrapKey, err := deriveKey(masterKey, hdr.salt, "ENVE1/wrap")
	if err != nil {
		return err
	}
	wg, err := newGCM(wrapKey)
	if err != nil {
		return err
	}
	dataKey, err := wg.Open(nil, zeroNonce, hdr.wrapped, wrapAAD(context))
	if err != nil {
		return ErrAuth
	}
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

	chunkSize := int(hdr.chunkSize)
	fullCT := chunkSize + gcmTagLen
	headerHash := sha256.Sum256(rawHeader)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(rawHeader)

	tmp, err := os.CreateTemp(opts.tempDir(), "envelope-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	st := &chunkState{
		context:    context,
		headerHash: headerHash,
		prevTag:    make([]byte, gcmTagLen),
		mac:        mac,
		gcm:        cg,
		spool:      tmp,
	}

	// 用 32 字节回读窗口区分最后一块与尾部认证码。
	buf := make([]byte, fullCT+macLen)
	held := 0
	for {
		n, rerr := src.Read(buf[held:])
		held += n
		for held-macLen >= fullCT {
			if err := st.process(buf[:fullCT]); err != nil {
				return err
			}
			copy(buf, buf[fullCT:held])
			held -= fullCT
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
		if n == 0 {
			return ErrFormat // 防止异常 Reader 造成死循环
		}
	}
	if held < macLen {
		return ErrFormat
	}
	trailer := buf[held-macLen : held]
	last := buf[:held-macLen]
	if len(last) > 0 {
		if len(last) <= gcmTagLen {
			return ErrFormat
		}
		if err := st.process(last); err != nil {
			return err
		}
	}
	if st.index == 0 {
		return ErrFormat
	}

	var tail [16]byte
	binary.BigEndian.PutUint64(tail[0:8], st.index)
	binary.BigEndian.PutUint64(tail[8:16], st.total)
	mac.Write(tail[:])
	if !hmac.Equal(trailer, mac.Sum(nil)) {
		return ErrAuth
	}

	// 验证全部通过；第二遍从临时文件解密并输出明文。
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if afterSpoolHook != nil {
		afterSpoolHook(tmp)
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	return st.emit(dst, chunkSize)
}

// chunkState 跟踪分块验证/解密所需的链式状态。
type chunkState struct {
	context    []byte
	headerHash [32]byte
	prevTag    []byte
	mac        hashWriter
	gcm        cipher.AEAD
	spool      *os.File
	index      uint64
	total      uint64
}

type hashWriter interface {
	Write(p []byte) (int, error)
}

// process 验证一个密文分块并写入暂存文件（第一遍）。
func (st *chunkState) process(ct []byte) error {
	var nonce [gcmNonceLen]byte
	binary.BigEndian.PutUint64(nonce[4:], st.index)
	aad := chunkAAD(st.context, st.headerHash, st.prevTag, st.index)
	if _, err := st.gcm.Open(nil, nonce[:], ct, aad); err != nil {
		return ErrAuth
	}
	tag := ct[len(ct)-gcmTagLen:]
	st.mac.Write(tag)
	st.prevTag = append(st.prevTag[:0], tag...)
	st.total += uint64(len(ct) - gcmTagLen)
	st.index++
	return writeAll(st.spool, ct)
}

// emit 从暂存文件逐块解密，向调用方输出明文（第二遍）。
func (st *chunkState) emit(dst io.Writer, chunkSize int) error {
	fullCT := chunkSize + gcmTagLen
	buf := make([]byte, fullCT)
	prevTag := make([]byte, gcmTagLen)
	remaining := st.total
	var index uint64
	for remaining > 0 {
		plain := uint64(chunkSize)
		if remaining < plain {
			plain = remaining
		}
		ct := buf[:plain+uint64(gcmTagLen)]
		if _, err := io.ReadFull(st.spool, ct); err != nil {
			return err
		}
		var nonce [gcmNonceLen]byte
		binary.BigEndian.PutUint64(nonce[4:], index)
		out, err := st.gcm.Open(nil, nonce[:], ct, chunkAAD(st.context, st.headerHash, prevTag, index))
		if err != nil {
			return ErrAuth // 已验证过，理论上不可达
		}
		if err := writeAll(dst, out); err != nil {
			return err
		}
		prevTag = append(prevTag[:0], ct[len(ct)-gcmTagLen:]...)
		remaining -= plain
		index++
	}
	return nil
}
