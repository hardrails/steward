// Command stewardctl manages offline Steward admission artifacts.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/buildinfo"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
)

const maxArtifactBytes = dsse.DefaultMaxEnvelopeBytes

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "stewardctl:", err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return usage(stderr)
	}
	if arguments[0] == "version" || arguments[0] == "-version" {
		_, err := fmt.Fprintln(stdout, "stewardctl "+buildinfo.Resolve())
		return err
	}
	switch arguments[0] {
	case "keygen":
		return keygen(arguments[1:], stdout)
	case "capsule":
		return artifact(arguments[1:], stdout, admission.CapsulePayloadType)
	case "policy":
		return artifact(arguments[1:], stdout, admission.PolicyPayloadType)
	case "evidence":
		return verifyEvidence(arguments[1:], stdout)
	default:
		return usage(stderr)
	}
}

func usage(writer io.Writer) error {
	fmt.Fprintln(writer, "usage: stewardctl keygen -private-out FILE -public-out FILE [-key-id ID]")
	fmt.Fprintln(writer, "       stewardctl capsule sign|verify ...")
	fmt.Fprintln(writer, "       stewardctl policy sign|verify ...")
	fmt.Fprintln(writer, "       stewardctl evidence verify -in FILE -public-key FILE -node-id ID [-epoch N]")
	return errors.New("invalid command")
}

func verifyEvidence(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "verify" {
		return errors.New("evidence command requires verify")
	}
	flags := flag.NewFlagSet("evidence verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "framed evidence log")
	publicKeyPath := flags.String("public-key", "", "base64 Ed25519 public key")
	nodeID := flags.String("node-id", "", "expected node ID")
	epoch := flags.Uint64("epoch", 1, "expected evidence key epoch")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if *input == "" || *publicKeyPath == "" || *nodeID == "" || flags.NArg() != 0 {
		return errors.New("evidence verify requires -in, -public-key, and -node-id")
	}
	publicKey, err := readPublicKey(*publicKeyPath)
	if err != nil {
		return err
	}
	last, err := evidence.Verify(*input, publicKey, *nodeID, *epoch)
	if err != nil {
		return err
	}
	if last == nil {
		_, err = fmt.Fprintln(stdout, "valid empty evidence chain")
		return err
	}
	_, err = fmt.Fprintf(stdout, "valid evidence chain: node=%s epoch=%d sequence=%d\n", last.NodeID, last.Epoch, last.Sequence)
	return err
}

func keygen(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privateOut := flags.String("private-out", "", "PEM private key output")
	publicOut := flags.String("public-out", "", "base64 public key output")
	keyID := flags.String("key-id", "", "stable key identifier")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *privateOut == "" || *publicOut == "" || flags.NArg() != 0 {
		return errors.New("keygen requires -private-out and -public-out")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if *keyID == "" {
		*keyID = publicKeyID(publicKey)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	if err := writeNewFile(*privateOut, privatePEM, 0o600); err != nil {
		return err
	}
	if err := writeNewFile(*publicOut, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, *keyID)
	return err
}

func artifact(arguments []string, stdout io.Writer, payloadType string) error {
	if len(arguments) == 0 {
		return errors.New("artifact command requires sign or verify")
	}
	switch arguments[0] {
	case "sign":
		return signArtifact(arguments[1:], stdout, payloadType)
	case "verify":
		return verifyArtifact(arguments[1:], stdout, payloadType)
	default:
		return errors.New("artifact command requires sign or verify")
	}
}

func signArtifact(arguments []string, stdout io.Writer, payloadType string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "strict JSON payload")
	output := flags.String("out", "", "DSSE envelope output")
	privateKeyPath := flags.String("key", "", "PEM Ed25519 private key")
	keyID := flags.String("key-id", "", "signing key ID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *output == "" || *privateKeyPath == "" || *keyID == "" || flags.NArg() != 0 {
		return errors.New("sign requires -in, -out, -key, and -key-id")
	}
	payload, err := readBounded(*input)
	if err != nil {
		return err
	}
	if err := validatePayload(payload, payloadType); err != nil {
		return err
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	envelope, err := dsse.Sign(payloadType, payload, *keyID, privateKey)
	if err != nil {
		return err
	}
	encoded, err := dsse.Marshal(envelope)
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, encoded, 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, dsse.Digest(encoded))
	return err
}

func verifyArtifact(arguments []string, stdout io.Writer, payloadType string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "DSSE envelope input")
	publicKeyPath := flags.String("public-key", "", "base64 Ed25519 public key")
	keyID := flags.String("key-id", "", "trusted signing key ID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *publicKeyPath == "" || *keyID == "" || flags.NArg() != 0 {
		return errors.New("verify requires -in, -public-key, and -key-id")
	}
	raw, err := readBounded(*input)
	if err != nil {
		return err
	}
	key, err := readPublicKey(*publicKeyPath)
	if err != nil {
		return err
	}
	payload, _, err := dsse.Verify(raw, payloadType, map[string]ed25519.PublicKey{*keyID: key})
	if err != nil {
		return err
	}
	if err := validatePayload(payload, payloadType); err != nil {
		return err
	}
	_, err = stdout.Write(append(payload, '\n'))
	return err
}

func validatePayload(payload []byte, payloadType string) error {
	switch payloadType {
	case admission.CapsulePayloadType:
		var capsule admission.ProfileCapsule
		if err := dsse.DecodeStrictInto(payload, maxArtifactBytes, &capsule); err != nil {
			return err
		}
		return capsule.Validate(timeNow())
	case admission.PolicyPayloadType:
		var policy admission.SitePolicy
		if err := dsse.DecodeStrictInto(payload, maxArtifactBytes, &policy); err != nil {
			return err
		}
		return policy.Validate()
	default:
		return errors.New("unsupported payload type")
	}
}

// timeNow is replaceable in tests without expanding the command-line contract.
var timeNow = func() time.Time { return time.Now().UTC() }

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("private key must be one PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return privateKey, nil
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("public key is not base64 Ed25519")
	}
	return ed25519.PublicKey(decoded), nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxArtifactBytes {
		return nil, errors.New("input is empty or exceeds 1 MiB")
	}
	return data, nil
}

func writeNewFile(path string, contents []byte, mode os.FileMode) error {
	if path == "" || !filepath.IsAbs(path) && strings.Contains(path, "..") {
		return errors.New("invalid output path")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(contents)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func publicKeyID(key ed25519.PublicKey) string { return dsse.Digest(key) }
