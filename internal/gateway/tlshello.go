package gateway

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	maxTLSClientHello       = 64 << 10
	maxTLSClientHelloRecord = (1 << 14) + 2048
	maxTLSHelloRecords      = 8
)

// readTLSClientHello reads and retains the bounded TLS records that contain the
// first ClientHello. The caller forwards the returned bytes only after the SNI
// has been matched to the CONNECT authority, preserving end-to-end TLS without
// trusting a shared destination IP to identify one virtual host.
func readTLSClientHello(reader io.Reader) ([]byte, string, error) {
	var raw, handshake []byte
	for record := 0; record < maxTLSHelloRecords; record++ {
		var header [5]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return nil, "", fmt.Errorf("read TLS record header: %w", err)
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || length < 1 || length > maxTLSClientHelloRecord {
			return nil, "", errors.New("invalid TLS ClientHello record")
		}
		if len(raw)+len(header)+length > maxTLSClientHello+(maxTLSHelloRecords*5) {
			return nil, "", errors.New("TLS ClientHello exceeds limit")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, "", fmt.Errorf("read TLS record: %w", err)
		}
		raw = append(raw, header[:]...)
		raw = append(raw, payload...)
		handshake = append(handshake, payload...)
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 {
			return nil, "", errors.New("first TLS handshake message is not ClientHello")
		}
		messageLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if messageLength < 1 || messageLength > maxTLSClientHello {
			return nil, "", errors.New("invalid TLS ClientHello length")
		}
		if len(handshake) < 4+messageLength {
			continue
		}
		name, err := parseTLSClientHelloServerName(handshake[4 : 4+messageLength])
		if err != nil {
			return nil, "", err
		}
		return raw, name, nil
	}
	return nil, "", errors.New("TLS ClientHello is too fragmented")
}

func parseTLSClientHelloServerName(hello []byte) (string, error) {
	cursor := helloCursor{raw: hello}
	if _, ok := cursor.take(2 + 32); !ok {
		return "", errors.New("truncated TLS ClientHello")
	}
	if _, ok := cursor.vector8(); !ok {
		return "", errors.New("invalid TLS session ID")
	}
	ciphers, ok := cursor.vector16()
	if !ok || len(ciphers) == 0 || len(ciphers)%2 != 0 {
		return "", errors.New("invalid TLS cipher suites")
	}
	compression, ok := cursor.vector8()
	if !ok || len(compression) == 0 {
		return "", errors.New("invalid TLS compression methods")
	}
	if cursor.remaining() == 0 {
		return "", nil
	}
	extensions, ok := cursor.vector16()
	if !ok || cursor.remaining() != 0 {
		return "", errors.New("invalid TLS extensions")
	}
	extensionCursor := helloCursor{raw: extensions}
	serverNameSeen := false
	serverName := ""
	for extensionCursor.remaining() > 0 {
		typeBytes, typeOK := extensionCursor.take(2)
		value, valueOK := extensionCursor.vector16()
		if !typeOK || !valueOK {
			return "", errors.New("truncated TLS extension")
		}
		if binary.BigEndian.Uint16(typeBytes) != 0 {
			continue
		}
		if serverNameSeen {
			return "", errors.New("duplicate TLS server name extension")
		}
		serverNameSeen = true
		name, err := parseTLSServerNameExtension(value)
		if err != nil {
			return "", err
		}
		serverName = name
	}
	return serverName, nil
}

func parseTLSServerNameExtension(extension []byte) (string, error) {
	cursor := helloCursor{raw: extension}
	names, ok := cursor.vector16()
	if !ok || cursor.remaining() != 0 || len(names) == 0 {
		return "", errors.New("invalid TLS server name list")
	}
	nameCursor := helloCursor{raw: names}
	serverName := ""
	for nameCursor.remaining() > 0 {
		nameType, ok := nameCursor.take(1)
		if !ok {
			return "", errors.New("truncated TLS server name")
		}
		name, ok := nameCursor.vector16()
		if !ok || len(name) == 0 {
			return "", errors.New("invalid TLS server name")
		}
		if nameType[0] != 0 {
			continue
		}
		if serverName != "" {
			return "", errors.New("duplicate TLS host name")
		}
		serverName = strings.ToLower(strings.TrimSuffix(string(name), "."))
		if strings.HasPrefix(serverName, "*.") || len(serverName) > 253 || !egressHostPattern.MatchString(serverName) || net.ParseIP(serverName) != nil {
			return "", errors.New("invalid TLS host name")
		}
	}
	return serverName, nil
}

type helloCursor struct {
	raw    []byte
	offset int
}

func (c *helloCursor) remaining() int { return len(c.raw) - c.offset }

func (c *helloCursor) take(length int) ([]byte, bool) {
	if length < 0 || length > c.remaining() {
		return nil, false
	}
	value := c.raw[c.offset : c.offset+length]
	c.offset += length
	return value, true
}

func (c *helloCursor) vector8() ([]byte, bool) {
	length, ok := c.take(1)
	if !ok {
		return nil, false
	}
	return c.take(int(length[0]))
}

func (c *helloCursor) vector16() ([]byte, bool) {
	length, ok := c.take(2)
	if !ok {
		return nil, false
	}
	return c.take(int(binary.BigEndian.Uint16(length)))
}
