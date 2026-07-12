package gateway

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

type zeroTestWriter struct{}

func (zeroTestWriter) Write([]byte) (int, error) { return 0, nil }

type errorTestWriter struct{ err error }

func (w errorTestWriter) Write([]byte) (int, error) { return 0, w.err }

func TestReadTLSClientHelloExtractsBoundedServerName(t *testing.T) {
	for _, expected := range []string{"api.example.com", ""} {
		agent, gateway := net.Pipe()
		done := make(chan error, 1)
		go func() {
			client := tls.Client(agent, &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 -- no server exists in this parser-only test.
				MinVersion:         tls.VersionTLS12,
				ServerName:         expected,
			})
			done <- client.Handshake()
			_ = client.Close()
		}()
		raw, name, err := readTLSClientHello(gateway)
		_ = gateway.Close()
		<-done
		if err != nil || len(raw) == 0 || name != expected {
			t.Fatalf("expected=%q name=%q bytes=%d err=%v", expected, name, len(raw), err)
		}
	}
	for _, malformed := range []string{
		"short",
		"\x17\x03\x03\x00\x01x",
		"\x16\x03\x03\x00\x04\x02\x00\x00\x00",
	} {
		if _, _, err := readTLSClientHello(strings.NewReader(malformed)); err == nil {
			t.Fatalf("malformed ClientHello accepted: %q", malformed)
		}
	}
}

func TestWriteAllBytesRejectsShortAndFailedWrites(t *testing.T) {
	if err := writeAllBytes(io.Discard, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := writeAllBytes(zeroTestWriter{}, []byte("hello")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error=%v", err)
	}
	want := errors.New("write failed")
	if err := writeAllBytes(errorTestWriter{err: want}, []byte("hello")); !errors.Is(err, want) {
		t.Fatalf("failed write error=%v", err)
	}
}
