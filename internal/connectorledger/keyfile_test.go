package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestReadConnectorLedgerKeys(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.pem")
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	writeKey(t, privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	loadedPrivate, err := ReadPrivateKey(privatePath)
	if err != nil || !loadedPrivate.Equal(private) {
		t.Fatalf("private key equal=%t err=%v", loadedPrivate.Equal(private), err)
	}

	publicPath := filepath.Join(directory, "public.pem")
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	writeKey(t, publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	loadedPublic, err := ReadPublicKey(publicPath)
	if err != nil || !loadedPublic.Equal(public) {
		t.Fatalf("public key equal=%t err=%v", loadedPublic.Equal(public), err)
	}
}

func TestReadConnectorLedgerKeysRejectsUnsafeFiles(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(private)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})

	t.Run("permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private.pem")
		writeKey(t, path, encoded, 0o640)
		if _, err := ReadPrivateKey(path); err == nil {
			t.Fatal("group-readable private key accepted")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.pem")
		writeKey(t, target, encoded, 0o600)
		link := filepath.Join(directory, "link.pem")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPrivateKey(link); err == nil {
			t.Fatal("private-key symlink accepted")
		}
	})

	t.Run("extra block", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private.pem")
		writeKey(t, path, append(encoded, encoded...), 0o600)
		if _, err := ReadPrivateKey(path); err == nil {
			t.Fatal("multiple private-key blocks accepted")
		}
	})
}

func writeKey(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
}
