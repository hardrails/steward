// Command stewardctl manages offline Steward admission artifacts.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/buildinfo"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/securefile"
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
	case "key":
		return keyCommand(arguments[1:], stdout)
	case "capsule":
		return artifact(arguments[1:], stdout, admission.CapsulePayloadType)
	case "policy":
		return artifact(arguments[1:], stdout, admission.PolicyPayloadType)
	case "permit":
		return permitCommand(arguments[1:], stdout)
	case "task":
		return taskCommand(arguments[1:], stdout)
	case "executor-command":
		return executorCommand(arguments[1:], stdout)
	case "control":
		return controlCommand(arguments[1:], stdout)
	case "evidence":
		return evidenceCommand(arguments[1:], stdout)
	case "node":
		return nodeCommand(arguments[1:], stdout)
	case "gateway":
		return gatewayCommand(arguments[1:], stdout)
	case "image":
		return imageCommand(arguments[1:], stdout)
	case "upgrade":
		return upgradeCommand(arguments[1:], stdout)
	default:
		return usage(stderr)
	}
}

func usage(writer io.Writer) error {
	fmt.Fprintln(writer, "usage: stewardctl keygen -private-out FILE -public-out FILE [-key-id ID]")
	fmt.Fprintln(writer, "       stewardctl key match -private-key FILE -public-key FILE")
	fmt.Fprintln(writer, "       stewardctl capsule sign|verify ...")
	fmt.Fprintln(writer, "       stewardctl policy sign|verify ...")
	fmt.Fprintln(writer, "       stewardctl permit issue|verify|audit ...")
	fmt.Fprintln(writer, "       stewardctl task issue|verify|audit|submit|status|observe|wait ...")
	fmt.Fprintln(writer, "       stewardctl executor-command issue|verify ...")
	fmt.Fprintln(writer, "       stewardctl control pki|tenant|operator|enrollment|node|command|evidence ...")
	fmt.Fprintln(writer, "       stewardctl evidence verify|export -in FILE -public-key FILE -node-id ID [-epoch N] [-kind executor|connector]")
	fmt.Fprintln(writer, "       stewardctl node admit|status|logs|egress|start|stop|destroy|purge-state ...")
	fmt.Fprintln(writer, "       stewardctl gateway validate|route|connector|service ...")
	fmt.Fprintln(writer, "       stewardctl image inspect|import -archive FILE ...")
	fmt.Fprintln(writer, "       stewardctl upgrade check-drained|inspect-formats -signed-admission configured|unconfigured ...")
	return errors.New("invalid command")
}

func nodeCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("node command requires admit, status, logs, egress, start, stop, destroy, or purge-state")
	}
	action := arguments[0]
	flags := flag.NewFlagSet("node "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	nodeURL := flags.String("node-url", "http://127.0.0.1:8090", "loopback Executor origin")
	tokenFile := flags.String("token-file", "", "owner-only Executor token")
	runtimeRef := flags.String("runtime-ref", "", "opaque executor runtime ref")
	capsulePath := flags.String("capsule", "", "signed capsule DSSE envelope")
	intentPath := flags.String("intent", "", "strict instance intent JSON")
	tenantID := flags.String("tenant-id", "", "signed tenant identity")
	nodeID := flags.String("node-id", "", "signed node identity")
	lineageID := flags.String("lineage-id", "", "state lineage identity")
	generation := flags.Uint64("generation", 0, "signed instance generation")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if *tokenFile == "" || flags.NArg() != 0 {
		return errors.New("node command requires -token-file and no positional arguments")
	}
	client, err := nodeclient.NewFromTokenFile(*nodeURL, *tokenFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var result any
	switch action {
	case "admit":
		if *capsulePath == "" || *intentPath == "" || *runtimeRef != "" {
			return errors.New("node admit requires -capsule and -intent")
		}
		capsule, err := nodeclient.ReadBounded(*capsulePath, dsse.DefaultMaxEnvelopeBytes)
		if err != nil {
			return err
		}
		intentRaw, err := nodeclient.ReadBounded(*intentPath, maxArtifactBytes)
		if err != nil {
			return err
		}
		var intent admission.InstanceIntent
		if err := dsse.DecodeStrictInto(intentRaw, maxArtifactBytes, &intent); err != nil {
			return fmt.Errorf("decode instance intent: %w", err)
		}
		result, err = client.Admit(ctx, capsule, intent)
		if err != nil {
			return err
		}
	case "status", "logs", "egress", "start", "stop", "destroy":
		if *runtimeRef == "" || *capsulePath != "" || *intentPath != "" {
			return fmt.Errorf("node %s requires -runtime-ref", action)
		}
		switch action {
		case "status":
			result, err = client.Status(ctx, *runtimeRef)
		case "logs":
			result, err = client.Logs(ctx, *runtimeRef)
		case "egress":
			result, err = client.EgressStats(ctx, *runtimeRef)
		case "start":
			result, err = client.Start(ctx, *runtimeRef)
		case "stop":
			result, err = client.Stop(ctx, *runtimeRef)
		case "destroy":
			err = client.Destroy(ctx, *runtimeRef)
			result = map[string]any{"runtime_ref": *runtimeRef, "destroyed": err == nil}
		}
		if err != nil {
			return err
		}
	case "purge-state":
		if *tenantID == "" || *nodeID == "" || *lineageID == "" || *generation == 0 ||
			*runtimeRef != "" || *capsulePath != "" || *intentPath != "" {
			return errors.New("node purge-state requires -tenant-id, -node-id, -lineage-id, and -generation")
		}
		err = client.PurgeState(ctx, nodeclient.StatePurge{
			TenantID: *tenantID, NodeID: *nodeID, LineageID: *lineageID, Generation: *generation,
		})
		result = map[string]any{"tenant_id": *tenantID, "lineage_id": *lineageID, "purged": err == nil}
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported node command %q", action)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

type evidenceHeadOutput struct {
	NodeID    string `json:"node_id"`
	Epoch     uint64 `json:"epoch"`
	Sequence  uint64 `json:"sequence"`
	ChainHash string `json:"chain_hash"`
	KeyID     string `json:"key_id"`
}

type evidenceRecordOutput struct {
	Format        string `json:"format"`
	Kind          string `json:"kind"`
	SignedFrame   string `json:"signed_frame"`
	NodeID        string `json:"node_id"`
	Epoch         uint64 `json:"epoch"`
	Sequence      uint64 `json:"sequence"`
	PreviousHash  string `json:"previous_hash"`
	ChainHash     string `json:"chain_hash"`
	Event         string `json:"event"`
	TenantID      string `json:"tenant_id"`
	RuntimeRef    string `json:"runtime_ref"`
	CapsuleDigest string `json:"capsule_digest"`
	PolicyDigest  string `json:"policy_digest"`
	Generation    uint64 `json:"generation"`
	GrantID       string `json:"grant_id"`
	Outcome       string `json:"outcome"`
	ErrorCode     string `json:"error_code,omitempty"`
	MetadataHash  string `json:"metadata_hash,omitempty"`
}

func evidenceCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || (arguments[0] != "verify" && arguments[0] != "export") {
		return errors.New("evidence command requires verify or export")
	}
	action := arguments[0]
	flags := flag.NewFlagSet("evidence "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "framed evidence log or portable NDJSON export")
	publicKeyPath := flags.String("public-key", "", "base64 Ed25519 public key")
	nodeID := flags.String("node-id", "", "expected node ID")
	epoch := flags.Uint64("epoch", 1, "expected evidence key epoch")
	jsonOutput := flags.Bool("json", false, "emit a machine-readable verification result")
	expectedSequence := flags.String("expected-sequence", "", "externally retained final sequence")
	expectedChainHash := flags.String("expected-chain-hash", "", "externally retained sha256 chain hash")
	kind := flags.String("kind", "executor", "evidence kind: executor or connector")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if *input == "" || *publicKeyPath == "" || *nodeID == "" || flags.NArg() != 0 {
		return fmt.Errorf("evidence %s requires -in, -public-key, and -node-id", action)
	}
	if action == "export" && *jsonOutput {
		return errors.New("evidence export is always newline-delimited JSON; -json is only valid with verify")
	}
	if *kind != "executor" && *kind != "connector" {
		return errors.New("evidence -kind must be executor or connector")
	}
	if *kind == "connector" && action != "verify" {
		return errors.New("connector evidence is already portable newline-delimited DSSE; use evidence verify -kind connector")
	}
	publicKey, err := readPublicKey(*publicKeyPath)
	if err != nil {
		return err
	}
	if *kind == "connector" {
		head, err := connectorledger.VerifyRecords(*input, publicKey, *nodeID, *epoch, nil)
		if err != nil {
			return err
		}
		if err := checkExpectedConnectorHead(head, *expectedSequence, *expectedChainHash); err != nil {
			return err
		}
		output := evidenceHeadOutput{NodeID: head.NodeID, Epoch: head.Epoch, Sequence: head.Sequence, ChainHash: head.ChainHash, KeyID: head.KeyID}
		if *jsonOutput {
			return json.NewEncoder(stdout).Encode(struct {
				Valid bool               `json:"valid"`
				Kind  string             `json:"kind"`
				Head  evidenceHeadOutput `json:"head"`
			}{Valid: true, Kind: "connector", Head: output})
		}
		if head.Sequence == 0 {
			_, err = fmt.Fprintln(stdout, "valid empty connector evidence chain")
			return err
		}
		_, err = fmt.Fprintf(stdout, "valid connector evidence chain: node=%s epoch=%d sequence=%d\n", head.NodeID, head.Epoch, head.Sequence)
		return err
	}
	var head evidence.Head
	if action == "export" {
		head, err = evidence.VerifyRecords(*input, publicKey, *nodeID, *epoch, nil)
	} else {
		head, err = evidence.VerifyAnyRecords(*input, publicKey, *nodeID, *epoch, nil)
	}
	if err != nil {
		return err
	}
	if err := checkExpectedEvidenceHead(head, *expectedSequence, *expectedChainHash); err != nil {
		return err
	}
	if action == "export" {
		return exportEvidence(*input, publicKey, *nodeID, *epoch, head, stdout)
	}
	output := evidenceHead(head)
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(struct {
			Valid bool               `json:"valid"`
			Head  evidenceHeadOutput `json:"head"`
		}{Valid: true, Head: output})
	}
	if head.Sequence == 0 {
		_, err = fmt.Fprintln(stdout, "valid empty evidence chain")
		return err
	}
	_, err = fmt.Fprintf(stdout, "valid evidence chain: node=%s epoch=%d sequence=%d\n", head.NodeID, head.Epoch, head.Sequence)
	return err
}

func checkExpectedConnectorHead(head connectorledger.Head, expectedSequence, expectedChainHash string) error {
	if expectedSequence != "" {
		sequence, err := strconv.ParseUint(expectedSequence, 10, 64)
		if err != nil {
			return errors.New("expected evidence sequence must be an unsigned decimal integer")
		}
		if head.Sequence != sequence {
			if head.Sequence < sequence {
				return fmt.Errorf("evidence rollback detected: expected sequence %d, verified %d", sequence, head.Sequence)
			}
			return fmt.Errorf("evidence checkpoint mismatch: expected sequence %d, verified advanced sequence %d", sequence, head.Sequence)
		}
	}
	if expectedChainHash != "" {
		if err := validateExpectedChainHash(expectedChainHash); err != nil {
			return err
		}
		if head.ChainHash != expectedChainHash {
			return fmt.Errorf("evidence checkpoint mismatch: expected chain hash %s, verified %s", expectedChainHash, head.ChainHash)
		}
	}
	return nil
}

func checkExpectedEvidenceHead(head evidence.Head, expectedSequence, expectedChainHash string) error {
	if expectedSequence != "" {
		sequence, err := strconv.ParseUint(expectedSequence, 10, 64)
		if err != nil {
			return errors.New("expected evidence sequence must be an unsigned decimal integer")
		}
		if head.Sequence != sequence {
			if head.Sequence < sequence {
				return fmt.Errorf("evidence rollback detected: expected sequence %d, verified %d", sequence, head.Sequence)
			}
			return fmt.Errorf("evidence checkpoint mismatch: expected sequence %d, verified advanced sequence %d", sequence, head.Sequence)
		}
	}
	if expectedChainHash != "" {
		if err := validateExpectedChainHash(expectedChainHash); err != nil {
			return err
		}
		if chainHash(head.ChainHash) != expectedChainHash {
			return fmt.Errorf("evidence checkpoint mismatch: expected chain hash %s, verified %s", expectedChainHash, chainHash(head.ChainHash))
		}
	}
	return nil
}

func validateExpectedChainHash(value string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return errors.New("expected evidence chain hash must be sha256 followed by 64 lowercase hexadecimal characters")
	}
	digest := strings.TrimPrefix(value, prefix)
	decoded, err := hex.DecodeString(digest)
	if err != nil || hex.EncodeToString(decoded) != digest {
		return errors.New("expected evidence chain hash must be sha256 followed by 64 lowercase hexadecimal characters")
	}
	return nil
}

func exportEvidence(path string, publicKey ed25519.PublicKey, nodeID string, epoch uint64, expected evidence.Head, stdout io.Writer) error {
	temporary, err := os.CreateTemp("", "steward-evidence-export-*")
	if err != nil {
		return fmt.Errorf("create verified evidence export: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	defer temporary.Close()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	encoder := json.NewEncoder(temporary)
	actual, err := evidence.VerifyRecords(path, publicKey, nodeID, epoch, func(verified evidence.VerifiedReceipt) error {
		receipt := verified.Receipt
		return encoder.Encode(evidenceRecordOutput{
			Format: evidence.ExportFormat, Kind: "receipt", SignedFrame: base64.StdEncoding.EncodeToString(verified.Frame),
			NodeID: receipt.NodeID, Epoch: receipt.Epoch, Sequence: receipt.Sequence,
			PreviousHash: chainHash(receipt.PreviousHash), ChainHash: chainHash(verified.ChainHash),
			Event: evidence.EventName(receipt.Type), TenantID: receipt.TenantID, RuntimeRef: receipt.RuntimeRef,
			CapsuleDigest: receipt.CapsuleDigest, PolicyDigest: receipt.PolicyDigest, Generation: receipt.Generation,
			GrantID: receipt.GrantID, Outcome: evidence.OutcomeName(receipt.Outcome),
			ErrorCode: receipt.ErrorCode, MetadataHash: receipt.MetadataHash,
		})
	})
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("evidence log changed during export; retry against a stable file")
	}
	if err := encoder.Encode(struct {
		Format string             `json:"format"`
		Kind   string             `json:"kind"`
		Head   evidenceHeadOutput `json:"head"`
	}{Format: evidence.ExportFormat, Kind: "head", Head: evidenceHead(actual)}); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err = io.Copy(stdout, temporary)
	return err
}

func evidenceHead(head evidence.Head) evidenceHeadOutput {
	return evidenceHeadOutput{NodeID: head.NodeID, Epoch: head.Epoch, Sequence: head.Sequence,
		ChainHash: chainHash(head.ChainHash), KeyID: head.KeyID}
}

func chainHash(hash [32]byte) string {
	return "sha256:" + hex.EncodeToString(hash[:])
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

func keyCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "match" {
		return errors.New("key command requires match")
	}
	flags := flag.NewFlagSet("key match", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privateKeyPath := flags.String("private-key", "", "PEM Ed25519 private key")
	publicKeyPath := flags.String("public-key", "", "base64 Ed25519 public key")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if *privateKeyPath == "" || *publicKeyPath == "" || flags.NArg() != 0 {
		return errors.New("key match requires -private-key and -public-key")
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	publicKey, err := readPublicKey(*publicKeyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	derivedPublicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("private key does not contain an Ed25519 public key")
	}
	if subtle.ConstantTimeCompare(derivedPublicKey, publicKey) != 1 {
		return errors.New("Ed25519 private and public keys do not match")
	}
	_, err = fmt.Fprintln(stdout, "Ed25519 key pair matches")
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
	case admission.CommandPayloadType:
		var command admission.CommandStatement
		if err := dsse.DecodeStrictInto(payload, maxArtifactBytes, &command); err != nil {
			return err
		}
		return command.Validate(timeNow())
	default:
		return errors.New("unsupported payload type")
	}
}

// timeNow is replaceable in tests without expanding the command-line contract.
var timeNow = func() time.Time { return time.Now().UTC() }

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := securefile.Read(path, maxArtifactBytes, securefile.OwnerOnly)
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
	raw, err := securefile.Read(path, maxArtifactBytes, securefile.TrustFile)
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
	return securefile.Read(path, maxArtifactBytes, securefile.Regular)
}

func writeNewFile(path string, contents []byte, mode os.FileMode) error {
	if path == "" || !filepath.IsAbs(path) && strings.Contains(path, "..") {
		return errors.New("invalid output path")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	cleanup := func(cause error) error {
		closeErr := file.Close()
		removeErr := os.Remove(path)
		syncErr := syncOutputDirectory(path)
		return errors.Join(cause, closeErr, removeErr, syncErr)
	}
	for written := 0; written < len(contents); {
		count, writeErr := file.Write(contents[written:])
		if writeErr != nil {
			return cleanup(writeErr)
		}
		if count <= 0 {
			return cleanup(io.ErrShortWrite)
		}
		written += count
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		removeErr := os.Remove(path)
		syncErr := syncOutputDirectory(path)
		return errors.Join(err, removeErr, syncErr)
	}
	if err := syncOutputDirectory(path); err != nil {
		removeErr := os.Remove(path)
		cleanupSyncErr := syncOutputDirectory(path)
		return errors.Join(err, removeErr, cleanupSyncErr)
	}
	return nil
}

func syncOutputDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func publicKeyID(key ed25519.PublicKey) string { return dsse.Digest(key) }
