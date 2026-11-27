package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type controlledReadCloser struct {
	reader   io.Reader
	readErr  error
	closeErr error
	closed   bool
}

func (r *controlledReadCloser) Read(buffer []byte) (int, error) {
	if r.readErr != nil {
		return 0, r.readErr
	}
	return r.reader.Read(buffer)
}

func (r *controlledReadCloser) Close() error {
	r.closed = true
	return r.closeErr
}

func TestDigestReadCloserStreamsAndPropagatesFailures(t *testing.T) {
	content := bytes.Repeat([]byte("payload-block-"), 8192)
	expected := sha256.Sum256(content)
	buffer := make([]byte, payloadHashBufferSize)

	t.Run("digest and close", func(t *testing.T) {
		reader := &controlledReadCloser{reader: bytes.NewReader(content)}
		got, err := digestReadCloser(reader, buffer, nil)
		if err != nil || got != expected || !reader.closed {
			t.Fatalf("digest=%x err=%v closed=%t", got, err, reader.closed)
		}
	})
	t.Run("read error still closes", func(t *testing.T) {
		readErr := errors.New("injected read error")
		reader := &controlledReadCloser{reader: bytes.NewReader(content), readErr: readErr}
		if _, err := digestReadCloser(reader, buffer, nil); !errors.Is(err, readErr) || !reader.closed {
			t.Fatalf("err=%v closed=%t", err, reader.closed)
		}
	})
	t.Run("close error invalidates digest", func(t *testing.T) {
		closeErr := errors.New("injected close error")
		reader := &controlledReadCloser{reader: bytes.NewReader(content), closeErr: closeErr}
		if _, err := digestReadCloser(reader, buffer, nil); !errors.Is(err, closeErr) || !reader.closed {
			t.Fatalf("err=%v closed=%t", err, reader.closed)
		}
	})
}

func TestHashRegularFileMatchesSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.bin")
	content := bytes.Repeat([]byte{0, 1, 2, 3, 255}, 257*1024)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := hashRegularFile(path, make([]byte, payloadHashBufferSize))
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256(content); got != want {
		t.Fatalf("digest mismatch: got %x want %x", got, want)
	}
}
