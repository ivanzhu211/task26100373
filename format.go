package envelope

import (
	"bytes"
	"encoding/binary"
	"io"
)

// 密文格式常量与头部编解码。
//
// 布局：
//
//	small:   magic(4) version(1) mode(1=0) salt(32) | ct+tag
//	chunked: magic(4) version(1) mode(1=1) salt(32) chunkSize(4,BE) wrappedKey(48) | 各分块 ct+tag... | trailer(32)
const (
	magicLen   = 4
	versionLen = 1
	modeLen    = 1

	modeSmall   byte = 0 // 明文 <= 4096 字节，直接用主密钥加密
	modeChunked byte = 1 // 明文 > 4096 字节，随机数据密钥分块加密

	formatVersion byte = 1

	saltLen       = 32 // HKDF 随机盐
	keyLen        = 32 // 256 位密钥
	gcmNonceLen   = 12
	gcmTagLen     = 16
	macLen        = 32 // HMAC-SHA256 尾部认证码
	smallMaxPlain = 4096

	defaultChunkSize = 1 << 20 // 1 MiB
	minChunkSize     = 64
	maxChunkSize     = 8 << 20 // 8 MiB，限制头部声明值，防止恶意输入撑爆内存
)

var magic = []byte{'E', 'N', 'V', '1'}

// header 是密文自包含头部的内存表示。
type header struct {
	mode      byte
	salt      []byte // small 模式：HKDF 盐；chunked 模式：包裹密钥的 HKDF 盐
	chunkSize uint32 // 仅 chunked 模式
	wrapped   []byte // 仅 chunked 模式：被包裹的数据密钥（密文+tag）
}

// encode 序列化头部。
func (h *header) encode() ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(magic)
	buf.WriteByte(formatVersion)
	buf.WriteByte(h.mode)
	buf.Write(h.salt)
	if h.mode == modeChunked {
		var tmp [4]byte
		binary.BigEndian.PutUint32(tmp[:], h.chunkSize)
		buf.Write(tmp[:])
		buf.Write(h.wrapped)
	}
	return buf.Bytes(), nil
}

// decodeHeader 从 r 读取并解析头部，同时返回原始头部字节（用于认证）。
func decodeHeader(r io.Reader) (*header, []byte, error) {
	var raw []byte
	take := func(n int) ([]byte, error) {
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, ErrFormat
		}
		raw = append(raw, buf...)
		return buf, nil
	}

	m, err := take(magicLen)
	if err != nil || !bytes.Equal(m, magic) {
		return nil, nil, ErrFormat
	}
	ver, err := take(versionLen)
	if err != nil || ver[0] != formatVersion {
		return nil, nil, ErrFormat
	}
	modeB, err := take(modeLen)
	if err != nil {
		return nil, nil, err
	}
	h := &header{mode: modeB[0]}
	switch h.mode {
	case modeSmall:
		if h.salt, err = take(saltLen); err != nil {
			return nil, nil, err
		}
	case modeChunked:
		if h.salt, err = take(saltLen); err != nil {
			return nil, nil, err
		}
		cs, err := take(4)
		if err != nil {
			return nil, nil, err
		}
		h.chunkSize = binary.BigEndian.Uint32(cs)
		if h.chunkSize < minChunkSize || h.chunkSize > maxChunkSize {
			return nil, nil, ErrFormat
		}
		if h.wrapped, err = take(keyLen + gcmTagLen); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, ErrFormat
	}
	// 拷贝盐与包裹密钥，避免共享底层缓冲被后续读取覆盖。
	h.salt = append([]byte(nil), h.salt...)
	h.wrapped = append([]byte(nil), h.wrapped...)
	return h, raw, nil
}
