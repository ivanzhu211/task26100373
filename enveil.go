// Package enveil provides streaming envelope encryption and decryption.
//
// Ciphertext is self-contained: given the same 256-bit master key and
// business context, any process can decrypt without side state.
// Decryption verifies the entire input before releasing any plaintext.
package enveil

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// DirectThreshold is the maximum plaintext size (in bytes) encrypted
// directly with the master key. Larger inputs use a random per-message
// data key wrapped by the master key.
const DirectThreshold = 4096

// KeySize is the required master key size in bytes (256 bits).
const KeySize = 32

var (
	// ErrKeySize reports a master key that is not 256 bits.
	ErrKeySize = errors.New("enveil: master key must be 32 bytes")
	// ErrMalformed reports structurally invalid ciphertext.
	ErrMalformed = errors.New("enveil: malformed ciphertext")
	// ErrAuth reports authentication failure: wrong key or context,
	// or tampered, truncated, extended, or spliced ciphertext.
	ErrAuth = errors.New("enveil: authentication failed")
)

// Option configures Encrypt or Decrypt.
type Option func(*config)

type config struct {
	tempDir string
}

// WithTempDir selects the directory for temporary ciphertext spool
// files used during decryption. The empty string means os.TempDir().
// Temporary files never contain plaintext or unwrapped data keys.
func WithTempDir(dir string) Option {
	return func(c *config) { c.tempDir = dir }
}

// Encrypt reads all plaintext from src and writes self-contained
// ciphertext to dst. masterKey must be 32 bytes; context is bound into
// the authenticity of the ciphertext but is not stored in it.
// Re-encrypting the same plaintext yields different ciphertext.
func Encrypt(dst io.Writer, src io.Reader, masterKey, context []byte, opts ...Option) error {
	if len(masterKey) != KeySize {
		return ErrKeySize
	}

	// Peek one byte past the direct threshold to choose the mode.
	peek := make([]byte, DirectThreshold+1)
	n, err := io.ReadFull(src, peek)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("enveil: reading plaintext: %w", err)
	}
	peek = peek[:n]

	if n <= DirectThreshold {
		// Direct mode: the whole plaintext is already buffered.
		h, err := newHeader(modeDirect)
		if err != nil {
			return err
		}
		contentKey, err := deriveContentKey(masterKey, h.salt, context)
		if err != nil {
			return err
		}
		defer clear(contentKey)
		aead, err := gcm(contentKey)
		if err != nil {
			return err
		}
		headerBytes := h.encode()
		if _, err := dst.Write(headerBytes); err != nil {
			return fmt.Errorf("enveil: writing ciphertext: %w", err)
		}
		return sealChunks(dst, bytes.NewReader(peek), aead, h.salt[:4], headerBytes)
	}

	// Envelope mode: random per-message data key, wrapped by a key
	// derived from the master key.
	h, err := newHeader(modeEnvelope)
	if err != nil {
		return err
	}
	dataKey := make([]byte, dataKeyLen)
	defer clear(dataKey)
	if _, err := rand.Read(dataKey); err != nil {
		return err
	}
	h.wrapNonce, h.wrapped, err = wrapDataKey(masterKey, h.salt, context, dataKey)
	if err != nil {
		return err
	}
	aead, err := gcm(dataKey)
	if err != nil {
		return err
	}
	headerBytes := h.encode()
	if _, err := dst.Write(headerBytes); err != nil {
		return fmt.Errorf("enveil: writing ciphertext: %w", err)
	}
	return sealChunks(dst, io.MultiReader(bytes.NewReader(peek), src), aead, h.salt[:4], headerBytes)
}

// Decrypt reads ciphertext from src and, only after the entire input is
// verified as authentic and complete, writes plaintext to dst. On any
// failure dst receives zero bytes. A temporary spool file holds
// ciphertext (never plaintext) during verification.
func Decrypt(dst io.Writer, src io.Reader, masterKey, context []byte, opts ...Option) error {
	if len(masterKey) != KeySize {
		return ErrKeySize
	}
	cfg := config{}
	for _, opt := range opts {
		opt(&cfg)
	}

	h, headerBytes, err := readHeader(src)
	if err != nil {
		return err
	}

	var contentKey []byte
	switch h.mode {
	case modeDirect:
		contentKey, err = deriveContentKey(masterKey, h.salt, context)
	case modeEnvelope:
		contentKey, err = unwrapDataKey(masterKey, h.salt, context, h.wrapNonce, h.wrapped)
	}
	if err != nil {
		return err
	}
	defer clear(contentKey)
	aead, err := gcm(contentKey)
	if err != nil {
		return err
	}

	// Pass 1: verify the whole stream while spooling ciphertext.
	sp, err := newSpool(cfg.tempDir)
	if err != nil {
		return fmt.Errorf("enveil: creating spool: %w", err)
	}
	defer sp.Close()
	if err := verifyChunks(sp, src, aead, h.salt[:4], headerBytes); err != nil {
		return err
	}

	// Pass 2: the input is authentic and complete; release plaintext.
	r, err := sp.Reader()
	if err != nil {
		return fmt.Errorf("enveil: reading spool: %w", err)
	}
	return openChunks(dst, r, aead, h.salt[:4], headerBytes)
}
