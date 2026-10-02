package enveil

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
)

// Encryption modes. The mode byte is part of the authenticated header
// and also selects the HKDF purpose, so it is bound twice.
const (
	modeDirect   byte = 0
	modeEnvelope byte = 1
)

const (
	magicLen     = 4
	saltLen      = 16
	wrapNonceLen = 12
	dataKeyLen   = 32
	gcmTagLen    = 16
	wrappedLen   = dataKeyLen + gcmTagLen
	// fixedLen is the header length before mode-specific fields.
	fixedLen = magicLen + 1 + saltLen
	// maxLen is the largest possible encoded header.
	maxLen = fixedLen + wrapNonceLen + wrappedLen
)

var magic = [magicLen]byte{'E', 'N', 'V', '1'}

// header is the self-contained ciphertext preamble. The full encoded
// header is bound into every chunk as associated data.
type header struct {
	mode      byte
	salt      []byte
	wrapNonce []byte // envelope mode only
	wrapped   []byte // envelope mode only
}

// newHeader creates a header with a fresh random salt.
func newHeader(mode byte) (header, error) {
	h := header{mode: mode, salt: make([]byte, saltLen)}
	if _, err := rand.Read(h.salt); err != nil {
		return header{}, err
	}
	return h, nil
}

// encode serializes h.
func (h *header) encode() []byte {
	buf := make([]byte, 0, maxLen)
	buf = append(buf, magic[:]...)
	buf = append(buf, h.mode)
	buf = append(buf, h.salt...)
	if h.mode == modeEnvelope {
		buf = append(buf, h.wrapNonce...)
		buf = append(buf, h.wrapped...)
	}
	return buf
}

// readHeader reads and parses a header from r, returning the header and
// its exact encoded bytes (used as associated data).
func readHeader(r io.Reader) (header, []byte, error) {
	fixed := make([]byte, fixedLen)
	if _, err := io.ReadFull(r, fixed); err != nil {
		return header{}, nil, fmt.Errorf("enveil: reading header: %w", err)
	}
	if !bytes.Equal(fixed[:magicLen], magic[:]) {
		return header{}, nil, ErrMalformed
	}
	h := header{mode: fixed[magicLen]}
	if h.mode != modeDirect && h.mode != modeEnvelope {
		return header{}, nil, ErrMalformed
	}
	h.salt = fixed[magicLen+1 : fixedLen]
	encoded := fixed
	if h.mode == modeEnvelope {
		rest := make([]byte, wrapNonceLen+wrappedLen)
		if _, err := io.ReadFull(r, rest); err != nil {
			return header{}, nil, fmt.Errorf("enveil: reading header: %w", err)
		}
		h.wrapNonce = rest[:wrapNonceLen]
		h.wrapped = rest[wrapNonceLen:]
		encoded = append(encoded, rest...)
	}
	return h, encoded, nil
}
