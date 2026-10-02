package enveil

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

// chunkSize is the plaintext payload per AEAD chunk in envelope mode.
const chunkSize = 1 << 20

// Chunk record wire format:
//
//	uint32 length   -- len(flags) + len(ciphertext), big endian
//	byte   flags    -- 0x00 normal, 0x01 final
//	byte[] ciphertext -- plaintext + 16-byte GCM tag
//
// The nonce is salt[0:4] || big-endian uint64 chunk counter, so chunks
// cannot be reordered, dropped, duplicated, or moved between messages
// (the salt differs per message and is authenticated in the header).
// The flags byte is part of the associated data, so the final mark
// cannot be forged or stripped.
const (
	flagFinal byte = 0x01

	lenSize      = 4
	maxRecordLen = 1 + chunkSize + gcmTagLen
)

// chunkNonce derives the nonce for chunk seq from the 4-byte base.
func chunkNonce(base []byte, seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, base)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

// chunkAD builds the associated data for a chunk: encoded header plus
// the flags byte.
func chunkAD(headerAD []byte, flags byte) []byte {
	ad := make([]byte, 0, len(headerAD)+1)
	ad = append(ad, headerAD...)
	ad = append(ad, flags)
	return ad
}

// writeRecord frames and writes one sealed chunk.
func writeRecord(dst io.Writer, aead cipher.AEAD, nonce, headerAD []byte, flags byte, plaintext []byte) error {
	record := make([]byte, 0, lenSize+maxRecordLen)
	var lenBuf [lenSize]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(1+len(plaintext)+aead.Overhead()))
	record = append(record, lenBuf[:]...)
	record = append(record, flags)
	record = aead.Seal(record, nonce, plaintext, chunkAD(headerAD, flags))
	_, err := dst.Write(record)
	return err
}

// sealChunks reads plaintext from src and writes framed AEAD chunks to
// dst, marking the final chunk. Empty plaintext yields one empty final
// chunk.
func sealChunks(dst io.Writer, src io.Reader, aead cipher.AEAD, nonceBase, headerAD []byte) error {
	buf := make([]byte, chunkSize)
	var seq uint64
	for {
		n, err := io.ReadFull(src, buf)
		final := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !final {
			return fmt.Errorf("enveil: reading plaintext: %w", err)
		}
		flags := byte(0)
		if final {
			flags = flagFinal
		}
		if err := writeRecord(dst, aead, chunkNonce(nonceBase, seq), headerAD, flags, buf[:n]); err != nil {
			return fmt.Errorf("enveil: writing ciphertext: %w", err)
		}
		seq++
		if final {
			return nil
		}
	}
}

// readRecord reads one framed chunk record from src. It returns
// io.EOF only when the stream ends cleanly at a record boundary.
// The returned slice aliases buf.
func readRecord(src io.Reader, buf []byte) (record []byte, err error) {
	var lenBuf [lenSize]byte
	if _, err := io.ReadFull(src, lenBuf[:]); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			return nil, ErrAuth // truncated inside a length prefix
		}
		return nil, fmt.Errorf("enveil: reading ciphertext: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 1+gcmTagLen || length > maxRecordLen {
		return nil, ErrMalformed
	}
	if int(length) > len(buf)-lenSize {
		return nil, ErrMalformed
	}
	record = buf[:lenSize+int(length)]
	copy(record, lenBuf[:])
	if _, err := io.ReadFull(src, record[lenSize:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, ErrAuth // truncated record
		}
		return nil, fmt.Errorf("enveil: reading ciphertext: %w", err)
	}
	return record, nil
}

// openRecord authenticates and opens one chunk record.
func openRecord(aead cipher.AEAD, nonce, headerAD, record []byte) (plaintext []byte, final bool, err error) {
	payload := record[lenSize:]
	flags := payload[0]
	if flags&^flagFinal != 0 {
		return nil, false, ErrMalformed
	}
	plaintext, err = aead.Open(nil, nonce, payload[1:], chunkAD(headerAD, flags))
	if err != nil {
		return nil, false, ErrAuth
	}
	return plaintext, flags&flagFinal != 0, nil
}

// verifyChunks reads framed chunks from src, verifies every chunk and
// the stream's finality, and spools the raw records to spool. It
// returns an error unless the input is a complete, authentic chunk
// stream ending with a final chunk and no trailing bytes.
func verifyChunks(spool io.Writer, src io.Reader, aead cipher.AEAD, nonceBase, headerAD []byte) error {
	buf := make([]byte, lenSize+maxRecordLen)
	var seq uint64
	for {
		record, err := readRecord(src, buf)
		if err == io.EOF {
			return ErrAuth // stream ended without a final chunk
		}
		if err != nil {
			return err
		}
		_, final, err := openRecord(aead, chunkNonce(nonceBase, seq), headerAD, record)
		if err != nil {
			return err
		}
		if _, err := spool.Write(record); err != nil {
			return fmt.Errorf("enveil: spooling ciphertext: %w", err)
		}
		seq++
		if final {
			// The final chunk must be the last thing in the stream.
			var extra [1]byte
			n, err := src.Read(extra[:])
			if n > 0 {
				return ErrAuth // trailing garbage after final chunk
			}
			if err != nil && err != io.EOF {
				return fmt.Errorf("enveil: reading ciphertext: %w", err)
			}
			return nil
		}
	}
}

// openChunks re-reads framed chunks from src (already verified) and
// writes plaintext to dst.
func openChunks(dst io.Writer, src io.Reader, aead cipher.AEAD, nonceBase, headerAD []byte) error {
	buf := make([]byte, lenSize+maxRecordLen)
	var seq uint64
	for {
		record, err := readRecord(src, buf)
		if err == io.EOF {
			return ErrAuth // unreachable after verifyChunks
		}
		if err != nil {
			return err
		}
		plaintext, final, err := openRecord(aead, chunkNonce(nonceBase, seq), headerAD, record)
		if err != nil {
			return err
		}
		if _, err := dst.Write(plaintext); err != nil {
			return fmt.Errorf("enveil: writing plaintext: %w", err)
		}
		seq++
		if final {
			return nil
		}
	}
}
