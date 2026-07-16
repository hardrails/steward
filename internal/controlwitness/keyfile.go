// Package controlwitness manages the dedicated Ed25519 key used to sign
// offline controller evidence-witness exports. This key is deliberately
// separate from TLS, bearer-authentication, tenant, and node receipt keys.
package controlwitness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hardrails/steward/internal/securefile"
)

const maxKeyFileBytes = 16 << 10

// Initialize creates one owner-only private key and its independently
// distributable public key. Both paths must be distinct files in the same
// owner-only directory. Existing files are never adopted or overwritten.
func Initialize(privatePath, publicPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	directory, err := validatePairPaths(privatePath, publicPath)
	if err != nil {
		return nil, nil, err
	}
	if err := validateDirectory(directory); err != nil {
		return nil, nil, err
	}
	if err := requireAbsent(privatePath); err != nil {
		return nil, nil, fmt.Errorf("initialize controller witness private key: %w", err)
	}
	if err := requireAbsent(publicPath); err != nil {
		return nil, nil, fmt.Errorf("initialize controller witness public key: %w", err)
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate controller witness key: %w", err)
	}
	privateRaw, err := marshalPrivate(private)
	if err != nil {
		return nil, nil, err
	}
	publicRaw, err := marshalPublic(public)
	if err != nil {
		return nil, nil, err
	}
	if err := writeExclusive(privatePath, privateRaw, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write controller witness private key: %w", err)
	}
	keepPrivate := false
	defer func() {
		if !keepPrivate {
			_ = os.Remove(privatePath)
			_ = syncDirectory(directory)
		}
	}()
	if err := writeExclusive(publicPath, publicRaw, 0o644); err != nil {
		return nil, nil, fmt.Errorf("write controller witness public key: %w", err)
	}
	keepPublic := false
	defer func() {
		if !keepPublic {
			_ = os.Remove(publicPath)
			_ = syncDirectory(directory)
		}
	}()
	if err := syncDirectory(directory); err != nil {
		return nil, nil, fmt.Errorf("sync controller witness key directory: %w", err)
	}
	keepPrivate, keepPublic = true, true
	return append(ed25519.PrivateKey(nil), private...), append(ed25519.PublicKey(nil), public...), nil
}

// LoadPair securely reads the private and public files and rejects a published
// public key that does not match the private key.
func LoadPair(privatePath, publicPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	directory, err := validatePairPaths(privatePath, publicPath)
	if err != nil {
		return nil, nil, err
	}
	if err := validateDirectory(directory); err != nil {
		return nil, nil, err
	}
	private, err := LoadPrivate(privatePath)
	if err != nil {
		return nil, nil, err
	}
	public, err := LoadPublic(publicPath)
	if err != nil {
		return nil, nil, err
	}
	derived := private.Public().(ed25519.PublicKey)
	if !bytes.Equal(derived, public) {
		return nil, nil, errors.New("controller witness public key does not match its private key")
	}
	return private, public, nil
}

// LoadPrivate securely reads one canonical owner-only PKCS#8 PEM Ed25519 key.
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("controller witness private key path must be clean and absolute")
	}
	raw, err := securefile.Read(path, maxKeyFileBytes, securefile.OwnerOnly)
	if err != nil {
		return nil, fmt.Errorf("read controller witness private key: %w", err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 || !bytes.Equal(raw, pem.EncodeToMemory(block)) {
		return nil, errors.New("controller witness private key must contain one canonical PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("controller witness private key is not valid PKCS#8")
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("controller witness private key is not Ed25519")
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil || !bytes.Equal(canonical, block.Bytes) {
		return nil, errors.New("controller witness private key is not canonical PKCS#8")
	}
	return append(ed25519.PrivateKey(nil), private...), nil
}

// LoadPublic securely reads one canonical SubjectPublicKeyInfo PEM Ed25519 key.
// The file may be world-readable but must not be writable by group or others.
func LoadPublic(path string) (ed25519.PublicKey, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("controller witness public key path must be clean and absolute")
	}
	raw, err := securefile.Read(path, maxKeyFileBytes, securefile.TrustFile)
	if err != nil {
		return nil, fmt.Errorf("read controller witness public key: %w", err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 || !bytes.Equal(raw, pem.EncodeToMemory(block)) {
		return nil, errors.New("controller witness public key must contain one canonical PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("controller witness public key is invalid")
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("controller witness public key is not Ed25519")
	}
	canonical, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(canonical, block.Bytes) {
		return nil, errors.New("controller witness public key is not canonical")
	}
	return append(ed25519.PublicKey(nil), public...), nil
}

func marshalPrivate(private ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("encode controller witness private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func marshalPublic(public ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("encode controller witness public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func validatePairPaths(privatePath, publicPath string) (string, error) {
	if !cleanAbsolute(privatePath) || !cleanAbsolute(publicPath) || privatePath == publicPath {
		return "", errors.New("controller witness key paths must be distinct, clean, and absolute")
	}
	privateDirectory := filepath.Dir(privatePath)
	if filepath.Dir(publicPath) != privateDirectory {
		return "", errors.New("controller witness key files must share one directory")
	}
	return privateDirectory, nil
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat controller witness key directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("controller witness key directory must be owner-only")
	}
	return nil
}

func requireAbsent(path string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return os.ErrExist
}

func writeExclusive(path string, raw []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := writeAll(file, raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func writeAll(file *os.File, raw []byte) error {
	for len(raw) > 0 {
		written, err := file.Write(raw)
		if err != nil {
			return err
		}
		if written <= 0 {
			return errors.New("write controller witness key: short write")
		}
		raw = raw[written:]
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
