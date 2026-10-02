package enveil

import (
	"os"
)

// spool is a temporary file holding ciphertext only. It never contains
// plaintext or unwrapped data keys.
type spool struct {
	f *os.File
}

// newSpool creates a temporary spool file in dir with owner-only
// permissions. An empty dir uses os.TempDir().
func newSpool(dir string) (*spool, error) {
	f, err := os.CreateTemp(dir, "enveil-spool-*")
	if err != nil {
		return nil, err
	}
	s := &spool{f: f}
	// Unlink immediately on success paths is handled by Close; on
	// creation failure of later steps callers must Close.
	return s, nil
}

// Write appends to the spool.
func (s *spool) Write(p []byte) (int, error) {
	return s.f.Write(p)
}

// Reader seeks the spool back to the start for reading.
func (s *spool) Reader() (*os.File, error) {
	if _, err := s.f.Seek(0, 0); err != nil {
		return nil, err
	}
	return s.f, nil
}

// Close removes the spool file.
func (s *spool) Close() error {
	name := s.f.Name()
	err := s.f.Close()
	if removeErr := os.Remove(name); err == nil {
		err = removeErr
	}
	return err
}
