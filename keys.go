package enveil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
)

// infoDirect and infoKEK separate the direct-mode content key from the
// envelope-mode key-encryption key, so the encryption mode is bound
// into key derivation. The business context is mixed into the HKDF
// info, so a different context yields different keys.
const (
	infoDirect = "enveil/v1/direct\x00"
	infoKEK    = "enveil/v1/kek\x00"
)

// hkdfKey derives a 256-bit key from masterKey, salt, and
// purpose||context as the HKDF-SHA256 info.
func hkdfKey(masterKey, salt []byte, purpose string, context []byte) ([]byte, error) {
	info := make([]byte, 0, len(purpose)+len(context))
	info = append(info, purpose...)
	info = append(info, context...)
	key, err := hkdf.Key(sha256.New, masterKey, salt, string(info), KeySize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// deriveContentKey derives the per-message content key for direct mode.
func deriveContentKey(masterKey, salt, context []byte) ([]byte, error) {
	return hkdfKey(masterKey, salt, infoDirect, context)
}

// wrapDataKey derives the key-encryption key and wraps dataKey with
// AES-256-GCM under a random nonce.
func wrapDataKey(masterKey, salt, context, dataKey []byte) (nonce, wrapped []byte, err error) {
	kek, err := hkdfKey(masterKey, salt, infoKEK, context)
	if err != nil {
		return nil, nil, err
	}
	defer clear(kek)
	aead, err := gcm(kek)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	// The salt authenticates the wrap to this specific message.
	wrapped = aead.Seal(nil, nonce, dataKey, salt)
	return nonce, wrapped, nil
}

// unwrapDataKey recovers the data key from its wrapped form.
func unwrapDataKey(masterKey, salt, context, nonce, wrapped []byte) ([]byte, error) {
	kek, err := hkdfKey(masterKey, salt, infoKEK, context)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	aead, err := gcm(kek)
	if err != nil {
		return nil, err
	}
	dataKey, err := aead.Open(nil, nonce, wrapped, salt)
	if err != nil {
		return nil, ErrAuth
	}
	return dataKey, nil
}

// gcm builds an AES-256-GCM AEAD from a 32-byte key.
func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
