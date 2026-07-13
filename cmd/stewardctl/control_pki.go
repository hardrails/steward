package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	defaultControlPKICAValidity     = 5 * 365 * 24 * time.Hour
	defaultControlPKIServerValidity = 365 * 24 * time.Hour
	minControlPKICAValidity         = 30 * 24 * time.Hour
	maxControlPKICAValidity         = 10 * 365 * 24 * time.Hour
	minControlPKIServerValidity     = time.Hour
	maxControlPKIServerValidity     = 398 * 24 * time.Hour
	controlPKIClockSkew             = 5 * time.Minute
	maxControlPKIServerNames        = 64
	maxControlPKIServerNamesBytes   = 4096
)

type controlPKIOutput struct {
	path     string
	contents []byte
	mode     os.FileMode
	file     *os.File
}

type controlPKISummary struct {
	CACertificateFingerprint     string   `json:"ca_certificate_fingerprint"`
	ServerCertificateFingerprint string   `json:"server_certificate_fingerprint"`
	DNSNames                     []string `json:"dns_names"`
	IPAddresses                  []string `json:"ip_addresses"`
	CANotAfter                   string   `json:"ca_not_after"`
	ServerNotAfter               string   `json:"server_not_after"`
}

func controlPKICreate(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control pki create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	caCertOut := flags.String("ca-cert-out", "", "new CA certificate PEM")
	caKeyOut := flags.String("ca-key-out", "", "new CA private key PEM")
	serverCertOut := flags.String("server-cert-out", "", "new control server certificate PEM")
	serverKeyOut := flags.String("server-key-out", "", "new control server private key PEM")
	serverNames := flags.String("server-names", "", "comma-separated DNS names and IP addresses")
	caValidFor := flags.Duration("ca-valid-for", defaultControlPKICAValidity, "CA certificate lifetime")
	serverValidFor := flags.Duration("server-valid-for", defaultControlPKIServerValidity, "server certificate lifetime")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("control pki create does not accept positional arguments")
	}

	dnsNames, ipAddresses, ipAddressStrings, err := canonicalControlPKIServerNames(*serverNames)
	if err != nil {
		return err
	}
	if err := validateControlPKIValidity(*caValidFor, *serverValidFor); err != nil {
		return err
	}
	outputs := []controlPKIOutput{
		{path: *caKeyOut, mode: 0o600},
		{path: *caCertOut, mode: 0o644},
		{path: *serverKeyOut, mode: 0o600},
		{path: *serverCertOut, mode: 0o644},
	}
	if err := validateControlPKIOutputPaths(outputs); err != nil {
		return err
	}

	material, summary, err := generateControlPKI(dnsNames, ipAddresses, ipAddressStrings, *caValidFor, *serverValidFor, time.Now())
	if err != nil {
		return err
	}
	outputs[0].contents = material.caKey
	outputs[1].contents = material.caCertificate
	outputs[2].contents = material.serverKey
	outputs[3].contents = material.serverCertificate
	if err := publishControlPKIFiles(outputs); err != nil {
		return err
	}
	if err := json.NewEncoder(stdout).Encode(summary); err != nil {
		return errors.Join(err, removeControlPKIFiles(outputs))
	}
	return nil
}

type controlPKIMaterial struct {
	caCertificate     []byte
	caKey             []byte
	serverCertificate []byte
	serverKey         []byte
}

func generateControlPKI(dnsNames []string, ipAddresses []net.IP, ipAddressStrings []string, caValidity, serverValidity time.Duration, now time.Time) (controlPKIMaterial, controlPKISummary, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, fmt.Errorf("generate control CA key: %w", err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, fmt.Errorf("generate control server key: %w", err)
	}
	caSerial, err := randomControlPKISerial()
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, fmt.Errorf("generate control CA serial: %w", err)
	}
	serverSerial, err := randomControlPKISerial()
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, fmt.Errorf("generate control server serial: %w", err)
	}
	caKeyID, err := controlPKIKeyID(&caKey.PublicKey)
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, err
	}
	serverKeyID, err := controlPKIKeyID(&serverKey.PublicKey)
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, err
	}

	now = now.UTC().Truncate(time.Second)
	notBefore := now.Add(-controlPKIClockSkew)
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Steward local control CA", Organization: []string{"Steward"}},
		NotBefore:             notBefore,
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          caKeyID,
	}
	caDER, err := x509.CreateCertificate(cryptorand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, fmt.Errorf("create control CA certificate: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          serverSerial,
		Subject:               pkix.Name{CommonName: "Steward Control", Organization: []string{"Steward"}},
		NotBefore:             notBefore,
		NotAfter:              now.Add(serverValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              append([]string(nil), dnsNames...),
		IPAddresses:           cloneControlPKIIPs(ipAddresses),
		SubjectKeyId:          serverKeyID,
		AuthorityKeyId:        append([]byte(nil), caKeyID...),
	}
	serverDER, err := x509.CreateCertificate(cryptorand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, fmt.Errorf("create control server certificate: %w", err)
	}
	caKeyPEM, err := marshalControlPKIKey(caKey)
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, fmt.Errorf("encode control CA key: %w", err)
	}
	serverKeyPEM, err := marshalControlPKIKey(serverKey)
	if err != nil {
		return controlPKIMaterial{}, controlPKISummary{}, fmt.Errorf("encode control server key: %w", err)
	}
	caFingerprint := sha256.Sum256(caDER)
	serverFingerprint := sha256.Sum256(serverDER)
	return controlPKIMaterial{
			caCertificate:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
			caKey:             caKeyPEM,
			serverCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
			serverKey:         serverKeyPEM,
		}, controlPKISummary{
			CACertificateFingerprint:     "sha256:" + hex.EncodeToString(caFingerprint[:]),
			ServerCertificateFingerprint: "sha256:" + hex.EncodeToString(serverFingerprint[:]),
			DNSNames:                     append([]string(nil), dnsNames...),
			IPAddresses:                  append([]string(nil), ipAddressStrings...),
			CANotAfter:                   caTemplate.NotAfter.Format(time.RFC3339),
			ServerNotAfter:               serverTemplate.NotAfter.Format(time.RFC3339),
		}, nil
}

func validateControlPKIValidity(caValidity, serverValidity time.Duration) error {
	if caValidity < minControlPKICAValidity || caValidity > maxControlPKICAValidity {
		return fmt.Errorf("CA validity must be between %s and %s", minControlPKICAValidity, maxControlPKICAValidity)
	}
	if serverValidity < minControlPKIServerValidity || serverValidity > maxControlPKIServerValidity {
		return fmt.Errorf("server validity must be between %s and %s", minControlPKIServerValidity, maxControlPKIServerValidity)
	}
	if serverValidity > caValidity {
		return errors.New("server validity must not exceed CA validity")
	}
	return nil
}

func canonicalControlPKIServerNames(value string) ([]string, []net.IP, []string, error) {
	if value == "" || len(value) > maxControlPKIServerNamesBytes {
		return nil, nil, nil, errors.New("control pki create requires 1 to 64 DNS names or IP addresses in -server-names")
	}
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > maxControlPKIServerNames {
		return nil, nil, nil, errors.New("control pki create requires 1 to 64 DNS names or IP addresses in -server-names")
	}
	dnsSeen := make(map[string]struct{}, len(parts))
	ipSeen := make(map[string]struct{}, len(parts))
	dnsNames := make([]string, 0, len(parts))
	ipStrings := make([]string, 0, len(parts))
	ipByString := make(map[string]net.IP, len(parts))
	for _, raw := range parts {
		name := strings.TrimSpace(raw)
		if name == "" {
			return nil, nil, nil, errors.New("server names must not contain empty entries")
		}
		if parsed := net.ParseIP(name); parsed != nil {
			canonicalIP := parsed.To16()
			if ipv4 := parsed.To4(); ipv4 != nil {
				canonicalIP = ipv4
			}
			canonical := canonicalIP.String()
			if _, duplicate := ipSeen[canonical]; duplicate {
				return nil, nil, nil, fmt.Errorf("server name %q is duplicated", canonical)
			}
			ipSeen[canonical] = struct{}{}
			ipStrings = append(ipStrings, canonical)
			ipByString[canonical] = append(net.IP(nil), canonicalIP...)
			continue
		}
		if looksLikeMalformedControlPKIIP(name) {
			return nil, nil, nil, fmt.Errorf("server name %q is not a canonical IP address", name)
		}
		canonical := strings.ToLower(strings.TrimSuffix(name, "."))
		if !validControlPKIDNSName(canonical) {
			return nil, nil, nil, fmt.Errorf("server name %q is not a valid ASCII DNS name or IP address", name)
		}
		if _, duplicate := dnsSeen[canonical]; duplicate {
			return nil, nil, nil, fmt.Errorf("server name %q is duplicated", canonical)
		}
		dnsSeen[canonical] = struct{}{}
		dnsNames = append(dnsNames, canonical)
	}
	sort.Strings(dnsNames)
	sort.Strings(ipStrings)
	ipAddresses := make([]net.IP, 0, len(ipStrings))
	for _, value := range ipStrings {
		ipAddresses = append(ipAddresses, append(net.IP(nil), ipByString[value]...))
	}
	return dnsNames, ipAddresses, ipStrings, nil
}

func looksLikeMalformedControlPKIIP(value string) bool {
	if strings.ContainsRune(value, ':') {
		return true
	}
	if !strings.ContainsRune(value, '.') {
		return false
	}
	for _, character := range value {
		if character != '.' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validControlPKIDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\x00:/%*") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !controlPKIDNSAlphaNumeric(label[0]) || !controlPKIDNSAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !controlPKIDNSAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func controlPKIDNSAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validateControlPKIOutputPaths(outputs []controlPKIOutput) error {
	seen := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		if output.path == "" || filepath.Clean(output.path) != output.path || output.path == "." || strings.ContainsRune(output.path, '\x00') {
			return errors.New("control pki create requires four clean output paths")
		}
		absolute, err := filepath.Abs(output.path)
		if err != nil {
			return fmt.Errorf("resolve output path %q: %w", output.path, err)
		}
		if _, duplicate := seen[absolute]; duplicate {
			return errors.New("control pki output paths must be distinct")
		}
		seen[absolute] = struct{}{}
		if _, err := os.Lstat(output.path); err == nil {
			return fmt.Errorf("control pki output path %q already exists", output.path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect control pki output path %q: %w", output.path, err)
		}
	}
	return nil
}

func publishControlPKIFiles(outputs []controlPKIOutput) error {
	reserved := 0
	for index := range outputs {
		file, err := os.OpenFile(outputs[index].path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return rollbackControlPKIFiles(outputs, reserved, fmt.Errorf("reserve control pki output %q: %w", outputs[index].path, err))
		}
		outputs[index].file = file
		reserved++
		if err := file.Chmod(outputs[index].mode); err != nil {
			return rollbackControlPKIFiles(outputs, reserved, fmt.Errorf("set control pki output mode %q: %w", outputs[index].path, err))
		}
	}
	for index := range outputs {
		for written := 0; written < len(outputs[index].contents); {
			count, err := outputs[index].file.Write(outputs[index].contents[written:])
			if err != nil {
				return rollbackControlPKIFiles(outputs, reserved, fmt.Errorf("write control pki output %q: %w", outputs[index].path, err))
			}
			if count <= 0 {
				return rollbackControlPKIFiles(outputs, reserved, fmt.Errorf("write control pki output %q: %w", outputs[index].path, io.ErrShortWrite))
			}
			written += count
		}
		if err := outputs[index].file.Sync(); err != nil {
			return rollbackControlPKIFiles(outputs, reserved, fmt.Errorf("sync control pki output %q: %w", outputs[index].path, err))
		}
	}
	for index := range outputs {
		err := outputs[index].file.Close()
		outputs[index].file = nil
		if err != nil {
			return rollbackControlPKIFiles(outputs, reserved, fmt.Errorf("close control pki output %q: %w", outputs[index].path, err))
		}
	}
	if err := syncControlPKIDirectories(outputs); err != nil {
		return rollbackControlPKIFiles(outputs, reserved, err)
	}
	return nil
}

func rollbackControlPKIFiles(outputs []controlPKIOutput, reserved int, cause error) error {
	errorsFound := []error{cause}
	for index := 0; index < reserved; index++ {
		if outputs[index].file != nil {
			errorsFound = append(errorsFound, outputs[index].file.Close())
			outputs[index].file = nil
		}
	}
	for index := reserved - 1; index >= 0; index-- {
		if err := os.Remove(outputs[index].path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errorsFound = append(errorsFound, err)
		}
	}
	if reserved > 0 {
		errorsFound = append(errorsFound, syncControlPKIDirectories(outputs[:reserved]))
	}
	return errors.Join(errorsFound...)
}

func removeControlPKIFiles(outputs []controlPKIOutput) error {
	errorsFound := make([]error, 0, len(outputs)+1)
	for index := len(outputs) - 1; index >= 0; index-- {
		if err := os.Remove(outputs[index].path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errorsFound = append(errorsFound, err)
		}
	}
	errorsFound = append(errorsFound, syncControlPKIDirectories(outputs))
	return errors.Join(errorsFound...)
}

func syncControlPKIDirectories(outputs []controlPKIOutput) error {
	directories := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		directories[filepath.Dir(output.path)] = struct{}{}
	}
	names := make([]string, 0, len(directories))
	for name := range directories {
		names = append(names, name)
	}
	sort.Strings(names)
	var errorsFound []error
	for _, name := range names {
		directory, err := os.Open(name)
		if err != nil {
			errorsFound = append(errorsFound, err)
			continue
		}
		errorsFound = append(errorsFound, directory.Sync(), directory.Close())
	}
	return errors.Join(errorsFound...)
}

func randomControlPKISerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := cryptorand.Int(cryptorand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

func controlPKIKeyID(publicKey *ecdsa.PublicKey) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("encode control pki public key: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return append([]byte(nil), digest[:20]...), nil
}

func marshalControlPKIKey(key *ecdsa.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

func cloneControlPKIIPs(values []net.IP) []net.IP {
	result := make([]net.IP, 0, len(values))
	for _, value := range values {
		result = append(result, append(net.IP(nil), value...))
	}
	return result
}
