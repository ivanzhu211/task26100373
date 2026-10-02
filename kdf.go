package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
)

// 本文件集中所有密钥派生与 AEAD 构造。
//
// 所有 GCM 实例的密钥均为单次使用（由随机盐或随机数据密钥派生），
// 因此使用全零 nonce 是安全的；分块正文除外——分块 nonce 由块序号构造，
// 在单次加密的密钥下唯一。

var zeroNonce = make([]byte, gcmNonceLen)

// deriveKey 用 HKDF-SHA256 从 secret 派生 32 字节密钥。
func deriveKey(secret, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, info, keyLen)
}

// newGCM 用 32 字节密钥构造 AES-256-GCM。
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// randBytes 返回 n 字节密码学随机数。
func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
