package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type controlPKITestPaths struct {
	caCert     string
	caKey      string
	serverCert string
	serverKey  string
}

func TestControlPKICreateBuildsVerifiableRestrictedChain(t *testing.T) {
	paths := newControlPKITestPaths(t.TempDir())
	started := time.Now().UTC()
	var stdout bytes.Buffer
	arguments := controlPKITestArguments(paths, "CONTROL.EXAMPLE., 2001:0DB8::1, 127.0.0.1,control.internal", defaultControlPKICAValidity, defaultControlPKIServerValidity)
	arguments = arguments[:len(arguments)-4] // Exercise the bounded production defaults.
	if err := controlCommand(arguments, &stdout); err != nil {
		t.Fatal(err)
	}

	caCertificate := readControlPKITestCertificate(t, paths.caCert)
	serverCertificate := readControlPKITestCertificate(t, paths.serverCert)
	caKey := readControlPKITestKey(t, paths.caKey)
	serverKey := readControlPKITestKey(t, paths.serverKey)
	if caKey.Curve != elliptic.P256() || serverKey.Curve != elliptic.P256() {
		t.Fatal("control PKI did not use ECDSA P-256 keys")
	}
	assertControlPKITestKeyMatches(t, caCertificate, caKey)
	assertControlPKITestKeyMatches(t, serverCertificate, serverKey)

	if !caCertificate.IsCA || !caCertificate.BasicConstraintsValid || !caCertificate.MaxPathLenZero || caCertificate.MaxPathLen != 0 {
		t.Fatalf("CA constraints=%#v", caCertificate)
	}
	if caCertificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(caCertificate.ExtKeyUsage) != 0 {
		t.Fatalf("CA usages key=%v extended=%v", caCertificate.KeyUsage, caCertificate.ExtKeyUsage)
	}
	if serverCertificate.IsCA || !serverCertificate.BasicConstraintsValid || serverCertificate.KeyUsage != x509.KeyUsageDigitalSignature || !reflect.DeepEqual(serverCertificate.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatalf("server constraints=%#v", serverCertificate)
	}
	if caCertificate.SerialNumber.Sign() <= 0 || serverCertificate.SerialNumber.Sign() <= 0 || caCertificate.SerialNumber.Cmp(serverCertificate.SerialNumber) == 0 {
		t.Fatalf("serials CA=%v server=%v", caCertificate.SerialNumber, serverCertificate.SerialNumber)
	}
	if err := caCertificate.CheckSignatureFrom(caCertificate); err != nil {
		t.Fatalf("CA is not self-signed: %v", err)
	}
	if err := serverCertificate.CheckSignatureFrom(caCertificate); err != nil {
		t.Fatalf("server certificate was not signed by CA: %v", err)
	}
	if !reflect.DeepEqual(serverCertificate.DNSNames, []string{"control.example", "control.internal"}) {
		t.Fatalf("DNS SANs=%v", serverCertificate.DNSNames)
	}
	gotIPs := make([]string, 0, len(serverCertificate.IPAddresses))
	for _, address := range serverCertificate.IPAddresses {
		gotIPs = append(gotIPs, address.String())
	}
	if !reflect.DeepEqual(gotIPs, []string{"127.0.0.1", "2001:db8::1"}) {
		t.Fatalf("IP SANs=%v", gotIPs)
	}
	if serverCertificate.NotAfter.After(caCertificate.NotAfter) {
		t.Fatalf("server expiry %s exceeds CA expiry %s", serverCertificate.NotAfter, caCertificate.NotAfter)
	}
	if caCertificate.NotBefore.After(started) || caCertificate.NotBefore.Before(started.Add(-controlPKIClockSkew-time.Minute)) {
		t.Fatalf("CA clock-skew window=%s started=%s", caCertificate.NotBefore, started)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	for _, name := range []string{"control.example", "control.internal", "127.0.0.1", "2001:db8::1"} {
		if _, err := serverCertificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: started.Add(time.Minute)}); err != nil {
			t.Fatalf("verify %q: %v", name, err)
		}
	}
	if _, err := serverCertificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("server certificate verified for an unrequested name")
	}

	for path, want := range map[string]os.FileMode{
		paths.caKey: 0o600, paths.serverKey: 0o600,
		paths.caCert: 0o644, paths.serverCert: 0o644,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("mode %s=%#o want %#o", path, got, want)
		}
	}

	var summary controlPKISummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("summary=%q: %v", stdout.String(), err)
	}
	caFingerprint := sha256.Sum256(caCertificate.Raw)
	serverFingerprint := sha256.Sum256(serverCertificate.Raw)
	if summary.CACertificateFingerprint != "sha256:"+hex.EncodeToString(caFingerprint[:]) ||
		summary.ServerCertificateFingerprint != "sha256:"+hex.EncodeToString(serverFingerprint[:]) ||
		!reflect.DeepEqual(summary.DNSNames, serverCertificate.DNSNames) ||
		!reflect.DeepEqual(summary.IPAddresses, gotIPs) {
		t.Fatalf("summary=%#v", summary)
	}
	var summaryFields map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &summaryFields); err != nil {
		t.Fatal(err)
	}
	if len(summaryFields) != 6 || bytes.Contains(stdout.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatalf("stdout contained unexpected or private data: %q", stdout.String())
	}
	for _, path := range []string{paths.caKey, paths.serverKey} {
		privatePEM, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(privatePEM)
		if block == nil {
			t.Fatal("private key PEM was not decodable")
		}
		if bytes.Contains(stdout.Bytes(), []byte(hex.EncodeToString(block.Bytes))) {
			t.Fatal("stdout disclosed private key bytes")
		}
	}
}

func TestControlPKICreateRejectsInvalidNamesAndValidity(t *testing.T) {
	tooManyNames := make([]string, maxControlPKIServerNames+1)
	for index := range tooManyNames {
		tooManyNames[index] = "host" + strconv.Itoa(index) + ".example"
	}
	cases := []struct {
		name           string
		serverNames    string
		caValidity     time.Duration
		serverValidity time.Duration
	}{
		{name: "missing names", caValidity: defaultControlPKICAValidity, serverValidity: defaultControlPKIServerValidity},
		{name: "empty entry", serverNames: "control.example,", caValidity: defaultControlPKICAValidity, serverValidity: defaultControlPKIServerValidity},
		{name: "duplicate canonical DNS", serverNames: "CONTROL.EXAMPLE,control.example.", caValidity: defaultControlPKICAValidity, serverValidity: defaultControlPKIServerValidity},
		{name: "wildcard", serverNames: "*.example", caValidity: defaultControlPKICAValidity, serverValidity: defaultControlPKIServerValidity},
		{name: "host port", serverNames: "control.example:8443", caValidity: defaultControlPKICAValidity, serverValidity: defaultControlPKIServerValidity},
		{name: "noncanonical IP", serverNames: "010.0.0.1", caValidity: defaultControlPKICAValidity, serverValidity: defaultControlPKIServerValidity},
		{name: "underscore", serverNames: "control_plane.example", caValidity: defaultControlPKICAValidity, serverValidity: defaultControlPKIServerValidity},
		{name: "unicode", serverNames: "contrôle.example", caValidity: defaultControlPKICAValidity, serverValidity: defaultControlPKIServerValidity},
		{name: "too many", serverNames: strings.Join(tooManyNames, ","), caValidity: defaultControlPKICAValidity, serverValidity: defaultControlPKIServerValidity},
		{name: "short CA", serverNames: "control.example", caValidity: minControlPKICAValidity - time.Second, serverValidity: minControlPKIServerValidity},
		{name: "long CA", serverNames: "control.example", caValidity: maxControlPKICAValidity + time.Second, serverValidity: defaultControlPKIServerValidity},
		{name: "short server", serverNames: "control.example", caValidity: defaultControlPKICAValidity, serverValidity: minControlPKIServerValidity - time.Second},
		{name: "long server", serverNames: "control.example", caValidity: defaultControlPKICAValidity, serverValidity: maxControlPKIServerValidity + time.Second},
		{name: "server outlives CA", serverNames: "control.example", caValidity: minControlPKICAValidity, serverValidity: minControlPKICAValidity + time.Second},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			paths := newControlPKITestPaths(t.TempDir())
			err := controlPKICreate(controlPKITestArguments(paths, test.serverNames, test.caValidity, test.serverValidity)[2:], io.Discard)
			if err == nil {
				t.Fatal("invalid control PKI request accepted")
			}
			assertControlPKITestPathsAbsent(t, paths)
		})
	}
}

func TestControlPKICreateRollsBackCollisionsAndOutputFailure(t *testing.T) {
	t.Run("reservation collision", func(t *testing.T) {
		directory := t.TempDir()
		collision := filepath.Join(directory, "collision.pem")
		if err := os.WriteFile(collision, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		outputs := []controlPKIOutput{
			{path: filepath.Join(directory, "first.pem"), contents: []byte("first"), mode: 0o600},
			{path: filepath.Join(directory, "second.pem"), contents: []byte("second"), mode: 0o644},
			{path: collision, contents: []byte("replacement"), mode: 0o600},
			{path: filepath.Join(directory, "fourth.pem"), contents: []byte("fourth"), mode: 0o644},
		}
		if err := publishControlPKIFiles(outputs); err == nil {
			t.Fatal("publication collision accepted")
		}
		if got, err := os.ReadFile(collision); err != nil || string(got) != "preserve" {
			t.Fatalf("collision target=%q error=%v", got, err)
		}
		for _, output := range []controlPKIOutput{outputs[0], outputs[1], outputs[3]} {
			if _, err := os.Lstat(output.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("reserved output %q remained: %v", output.path, err)
			}
		}
	})

	t.Run("stdout failure", func(t *testing.T) {
		paths := newControlPKITestPaths(t.TempDir())
		err := controlPKICreate(controlPKITestArguments(paths, "control.example", defaultControlPKICAValidity, defaultControlPKIServerValidity)[2:], errorControlPKITestWriter{})
		if err == nil {
			t.Fatal("stdout failure was ignored")
		}
		assertControlPKITestPathsAbsent(t, paths)
	})
}

func TestControlPKICreateRefusesExistingSymlinkAndUncleanPaths(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		paths := newControlPKITestPaths(directory)
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, paths.serverCert); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		err := controlPKICreate(controlPKITestArguments(paths, "control.example", defaultControlPKICAValidity, defaultControlPKIServerValidity)[2:], io.Discard)
		if err == nil {
			t.Fatal("symlink output accepted")
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != "preserve" {
			t.Fatalf("symlink target=%q error=%v", got, err)
		}
		for _, path := range []string{paths.caCert, paths.caKey, paths.serverKey} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected output %q: %v", path, err)
			}
		}
	})

	t.Run("unclean path", func(t *testing.T) {
		directory := t.TempDir()
		paths := newControlPKITestPaths(directory)
		paths.caCert = directory + string(os.PathSeparator) + "nested" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "ca.pem"
		if err := controlPKICreate(controlPKITestArguments(paths, "control.example", defaultControlPKICAValidity, defaultControlPKIServerValidity)[2:], io.Discard); err == nil {
			t.Fatal("unclean output path accepted")
		}
	})
}

type errorControlPKITestWriter struct{}

func (errorControlPKITestWriter) Write([]byte) (int, error) {
	return 0, errors.New("injected output failure")
}

func newControlPKITestPaths(directory string) controlPKITestPaths {
	return controlPKITestPaths{
		caCert:     filepath.Join(directory, "ca.pem"),
		caKey:      filepath.Join(directory, "ca-key.pem"),
		serverCert: filepath.Join(directory, "server.pem"),
		serverKey:  filepath.Join(directory, "server-key.pem"),
	}
}

func controlPKITestArguments(paths controlPKITestPaths, serverNames string, caValidity, serverValidity time.Duration) []string {
	return []string{
		"pki", "create",
		"-ca-cert-out", paths.caCert,
		"-ca-key-out", paths.caKey,
		"-server-cert-out", paths.serverCert,
		"-server-key-out", paths.serverKey,
		"-server-names", serverNames,
		"-ca-valid-for", caValidity.String(),
		"-server-valid-for", serverValidity.String(),
	}
}

func readControlPKITestCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("invalid certificate PEM %q", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func readControlPKITestKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("invalid private key PEM %q", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type=%T", parsed)
	}
	return key
}

func assertControlPKITestKeyMatches(t *testing.T, certificate *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != key.Curve || publicKey.X.Cmp(key.X) != 0 || publicKey.Y.Cmp(key.Y) != 0 {
		t.Fatal("certificate and private key do not match")
	}
}

func assertControlPKITestPathsAbsent(t *testing.T, paths controlPKITestPaths) {
	t.Helper()
	for _, path := range []string{paths.caCert, paths.caKey, paths.serverCert, paths.serverKey} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected output %q: %v", path, err)
		}
	}
}
