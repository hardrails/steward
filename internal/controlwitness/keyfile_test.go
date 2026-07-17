package controlwitness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInitializeAndLoadPair(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "witness")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "witness.private.pem")
	publicPath := filepath.Join(directory, "witness.public.pem")
	private, public, err := Initialize(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		t.Fatal("generated controller witness key pair does not match")
	}
	assertMode(t, privatePath, 0o600)
	assertMode(t, publicPath, 0o644)
	loadedPrivate, loadedPublic, err := LoadPair(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedPrivate, private) || !bytes.Equal(loadedPublic, public) {
		t.Fatal("loaded controller witness key pair changed bytes")
	}
	loadedPrivate[0] ^= 0xff
	loadedPublic[0] ^= 0xff
	privateAgain, publicAgain, err := LoadPair(privatePath, publicPath)
	if err != nil || !bytes.Equal(privateAgain, private) || !bytes.Equal(publicAgain, public) {
		t.Fatalf("controller witness loads do not return independent copies: %v", err)
	}
}

func TestParsePublicUsesExactCanonicalSnapshot(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalPublic(public)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublic(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, public) {
		t.Fatal("parsed controller witness public key changed bytes")
	}
	parsed[0] ^= 0xff
	parsedAgain, err := ParsePublic(raw)
	if err != nil || !bytes.Equal(parsedAgain, public) {
		t.Fatalf("parsed controller witness key aliases caller bytes: %v", err)
	}
	for _, invalid := range [][]byte{
		append(append([]byte(nil), raw...), '\n'),
		[]byte("not a PEM key"),
	} {
		if _, err := ParsePublic(invalid); err == nil {
			t.Fatal("non-canonical controller witness public key bytes were accepted")
		}
	}
}

func TestInitializeRefusesExistingPartialOrUnsafeState(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "witness")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "witness.private.pem")
	publicPath := filepath.Join(directory, "witness.public.pem")
	if err := os.WriteFile(privatePath, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Initialize(privatePath, publicPath); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing private key error = %v", err)
	}
	if _, err := os.Stat(publicPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public key unexpectedly created: %v", err)
	}
	if err := os.Remove(privatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Initialize(privatePath, publicPath); err == nil {
		t.Fatal("unsafe controller witness directory was accepted")
	}
	if _, _, err := Initialize(privatePath, privatePath); err == nil {
		t.Fatal("identical controller witness paths were accepted")
	}
	if _, _, err := Initialize(privatePath, filepath.Join(t.TempDir(), "public.pem")); err == nil {
		t.Fatal("controller witness paths in different directories were accepted")
	}
}

func TestLoadPairRejectsUnsafeFilesAndMismatch(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "witness")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "witness.private.pem")
	publicPath := filepath.Join(directory, "witness.public.pem")
	if _, _, err := Initialize(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(privatePath); err == nil {
		t.Fatal("group-readable controller witness private key was accepted")
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublic(publicPath); err == nil {
		t.Fatal("group-writable controller witness public key was accepted")
	}
	if err := os.Chmod(publicPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPair(privatePath, publicPath); err == nil {
		t.Fatal("controller witness pair in a group-accessible directory was accepted")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePublicForTest(publicPath, otherPublic); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPair(privatePath, publicPath); err == nil {
		t.Fatal("mismatched controller witness public key was accepted")
	}
}

func TestLoadRejectsNonCanonicalWrongTypeAndSymlink(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "witness")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "private.pem")
	publicPath := filepath.Join(directory, "public.pem")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateRaw, err := marshalPrivate(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privatePath, append(privateRaw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(privatePath); err == nil {
		t.Fatal("non-canonical controller witness private PEM was accepted")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	wrongType := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: publicDER})
	if err := os.WriteFile(publicPath, wrongType, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublic(publicPath); err == nil {
		t.Fatal("wrong controller witness public PEM type was accepted")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(directory, "private-link.pem")
		if err := os.Symlink(privatePath, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivate(link); err == nil {
			t.Fatal("controller witness private-key symlink was accepted")
		}
	}
}

func writePublicForTest(path string, public ed25519.PublicKey) error {
	raw, err := marshalPublic(public)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %s = %#o, want %#o", path, got, want)
	}
}
