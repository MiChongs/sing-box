package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type shortWriter struct {
	max int
	buf bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.buf.Write(p)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type identityWriter struct{ err error }

func (w identityWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriteFullHandlesShortWritesAndNoProgress(t *testing.T) {
	writer := &shortWriter{max: 1}
	if err := WriteFull(writer, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	if got := writer.buf.String(); got != "complete" {
		t.Fatalf("written %q", got)
	}
	if err := WriteFull(zeroWriter{}, []byte("x")); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("zero writer error = %v", err)
	}
}

func TestFramedWritesPreserveErrorIdentity(t *testing.T) {
	sentinel := errors.New("sentinel write failure")
	if err := WriteSetupResult(identityWriter{err: sentinel}, SetupResultReady); !errors.Is(err, sentinel) {
		t.Fatalf("setup result lost identity: %v", err)
	}
	if err := WriteUDPPacket(identityWriter{err: sentinel}, []byte("packet")); !errors.Is(err, sentinel) {
		t.Fatalf("UoT lost identity: %v", err)
	}
}

func TestFramedWritesHandleShortWrites(t *testing.T) {
	writer := &shortWriter{max: 1}
	if err := WriteSetupResult(writer, SetupResultReady); err != nil {
		t.Fatal(err)
	}
	if err := WriteUDPPacket(writer, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 3, 'a', 'b', 'c'}
	if !bytes.Equal(writer.buf.Bytes(), want) {
		t.Fatalf("written %x want %x", writer.buf.Bytes(), want)
	}
}
