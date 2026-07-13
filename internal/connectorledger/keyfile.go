package connectorledger

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxKeyFileBytes = 16 << 10

// ReadPrivateKey opens one owner-only PKCS#8 PEM Ed25519 key. It matches the
// private-key format written by stewardctl keygen.
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readKeyFile(path, true)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("connector receipt private key must contain one PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("connector receipt private key is not valid PKCS#8")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("connector receipt private key is not Ed25519")
	}
	return append(ed25519.PrivateKey(nil), key...), nil
}

// ReadPublicKey opens one SubjectPublicKeyInfo PEM Ed25519 key for offline
// connector-ledger verification.
func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := readKeyFile(path, false)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("connector receipt public key must contain one PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("connector receipt public key is invalid")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("connector receipt public key is not Ed25519")
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

func readKeyFile(path string, private bool) ([]byte, error) {
	if !validPath(path) {
		return nil, errors.New("connector receipt key path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxKeyFileBytes || private && info.Mode().Perm()&0o077 != 0 || !private && info.Mode().Perm()&0o022 != 0 {
		kind := "public"
		if private {
			kind = "private"
		}
		return nil, fmt.Errorf("connector receipt %s key must be a bounded regular file with safe permissions", kind)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() != info.Size() {
		return nil, errors.New("connector receipt key changed while opening")
	}
	raw := make([]byte, opened.Size())
	if _, err := io.ReadFull(file, raw); err != nil {
		return nil, err
	}
	return raw, nil
}
