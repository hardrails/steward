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
		return usage(stdout)
	}
	if arguments[0] == "version" || arguments[0] == "-version" {
		_, err := fmt.Fprintln(stdout, "stewardctl "+buildinfo.Resolve())
		return err
	}
	if arguments[0] == "__complete" {
		return writeCompletionCandidates(arguments[1:], stdout)
	}
	if arguments[0] == "help" || arguments[0] == "-help" || arguments[0] == "--help" {
		return helpCommand(arguments[1:], stdout)
	}
	switch arguments[0] {
	case "site":
		return siteCommand(arguments[1:], stdout)
	case "agent":
		return agentCommand(arguments[1:], stdout)
	case "context":
		return contextCommand(arguments[1:], stdout)
	case "completion":
		return completionCommand(arguments[1:], stdout)
	case "keygen":
		return keygen(arguments[1:], stdout)
	case "key":
		return keyCommand(arguments[1:], stdout)
	case "capsule":
		return capsuleCommand(arguments[1:], stdout)
	case "policy":
		return artifact(arguments[1:], stdout, admission.PolicyPayloadType)
	case "permit":
		return permitCommand(arguments[1:], stdout, stderr)
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
	case "secret":
		return secretCommand(arguments[1:], stdout)
	case "image":
		return imageCommand(arguments[1:], stdout)
	case "upgrade":
		return upgradeCommand(arguments[1:], stdout)
	default:
		return fmt.Errorf("unknown command %q; run 'stewardctl help'", arguments[0])
	}
}

func usage(writer io.Writer) error {
	fmt.Fprintln(writer, "Steward runs untrusted agents with external action authority.")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Usage:  stewardctl <command> [options]")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Start here")
	fmt.Fprintln(writer, "  site          Create and verify a secure site authority package")
	fmt.Fprintln(writer, "  agent         Initialize, build, place, and fork Hermes agents")
	fmt.Fprintln(writer, "  context       Save a control plane or node connection")
	fmt.Fprintln(writer, "  node          Admit, inspect, start, stop, or destroy an agent")
	fmt.Fprintln(writer, "  control       Enroll nodes and inspect the fleet")
	fmt.Fprintln(writer, "  permit        Authorize one exact external action")
	fmt.Fprintln(writer, "  task          Submit and observe an authorized agent task")
	fmt.Fprintln(writer, "  evidence      Verify or export signed enforcement records")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Configure and inspect")
	fmt.Fprintln(writer, "  image         Inspect or import an offline OCI image")
	fmt.Fprintln(writer, "  gateway       Validate routes, services, connectors, and effects")
	fmt.Fprintln(writer, "  secret        Validate materialized secret files")
	fmt.Fprintln(writer, "  capsule       Sign or verify an immutable workload profile")
	fmt.Fprintln(writer, "  policy        Sign or verify site policy")
	fmt.Fprintln(writer, "  keygen, key   Create or inspect signing keys")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Utilities")
	fmt.Fprintln(writer, "  completion    Install Bash, Zsh, or Fish completion")
	fmt.Fprintln(writer, "  upgrade       Inspect upgrade safety")
	fmt.Fprintln(writer, "  version       Print the installed version")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Run 'stewardctl help <command>' for command-specific guidance.")
	return nil
}

func helpCommand(arguments []string, writer io.Writer) error {
	if len(arguments) == 0 {
		return usage(writer)
	}
	if len(arguments) != 1 {
		return errors.New("help accepts one command name")
	}
	help, ok := commandHelp[arguments[0]]
	if !ok {
		return fmt.Errorf("unknown command %q; run 'stewardctl help'", arguments[0])
	}
	_, err := fmt.Fprint(writer, help)
	return err
}

var commandHelp = map[string]string{
	"site":             "Create a complete, offline-verifiable site authority package, establish least-privilege operator and task contexts, then prepare and activate finite node enrollment handoffs without transmitting tenant private keys.\n\nUsage: stewardctl site init DIRECTORY [options]\n       stewardctl site verify DIRECTORY [-site-root-public-key FILE]\n       stewardctl site connect DIRECTORY [options]\n       stewardctl site task connect DIRECTORY [options]\n       stewardctl site node prepare SITE_DIRECTORY NODE_ID [options]\n       stewardctl site node activate PACKAGE_DIRECTORY [options]\n       stewardctl site node verify PACKAGE_DIRECTORY [options]\n\nStart with: stewardctl site init steward-site -tenant-id default -control-server-names control.example.com\n",
	"agent":            "Build and run portable Hermes agent applications, evaluate offline policy, publish signed image authority, delegate finite controller authority, activate the bounded Gateway service, explain fleet placement, and converge durable deployments.\n\nUsage: stewardctl agent create|init|validate|build|publish|authorize|service|plan|apply|deploy|deployment|fork|doctor ...\n\nCreate a project with: stewardctl agent create NAME -runtime hermes\nPublish its inspected OCI archive with: stewardctl agent publish SITE_DIRECTORY -archive image.tar\nAuthorize its finite deployment with: stewardctl agent authorize SITE_DIRECTORY -node-ids node-a\nActivate its service on the destination node with: stewardctl agent service activate -tenant-id TENANT -node-id NODE\nApply durable desired state with: stewardctl agent apply NAME\nThe expert single-node form remains available as agent apply with named flags only.\n",
	"context":          "Save connection details once so routine commands do not repeat URLs, token files, tenant IDs, or node IDs.\n\nUsage: stewardctl context set|use|show|list|delete ...\n",
	"node":             "Operate one isolated agent on a Steward Executor node. After saving a context, pass the runtime reference directly: stewardctl node status executor-…\n\nUsage: stewardctl node whoami|admit|status|logs|egress|start|stop|destroy|snapshot-state|clone-state|delete-snapshot|purge-state|maintenance ...\n",
	"control":          "Enroll nodes, manage scoped operators, freeze command delivery during incidents, quarantine suspect snapshots, place and drain agent workloads, inspect fleet evidence, and create metadata-only support bundles.\n\nUsage: stewardctl control pki|tenant|operator|enrollment|node|snapshot|operations|quota|freeze|attention|agent|command|credential|evidence|evidence-capture|support-bundle ...\n",
	"permit":           "Authorize one canonical connector request without giving the action key or reusable upstream credential to the agent.\n\nUsage: stewardctl permit context|issue|approve|verify|audit ...\n",
	"task":             "Run, issue, submit, observe, and audit an authorized service task through Gateway. The run command persists the exact signed bundle before dispatch so an interrupted task can be resumed without minting new authority.\n\nUsage: stewardctl task run|issue|verify|audit|submit|status|observe|wait ...\n\nWith task defaults in a context: stewardctl task run DEPLOYMENT \"your request\"\n",
	"evidence":         "Verify or export a signed Executor or Gateway receipt chain without contacting a hosted service.\n\nUsage: stewardctl evidence verify|export ...\n",
	"image":            "Inspect or import one bounded offline OCI/Docker archive and bind it to the signed workload identity.\n\nUsage: stewardctl image inspect|import ...\n",
	"gateway":          "Validate the Gateway configuration, configure mediated inference providers, bind its enrolled node identity, and inspect routes, connectors, services, and effect policy.\n\nUsage: stewardctl gateway validate|identity|inference|route|connector|service|effects ...\n",
	"secret":           "Validate or prepare owner-only files rendered by an external secret materializer. Steward does not store secrets.\n\nUsage: stewardctl secret materialization check|prepare ...\n",
	"capsule":          "Check, sign, or verify a publisher workload profile against Steward's built-in runtime contract.\n\nUsage: stewardctl capsule check-profile|sign|verify ...\n",
	"policy":           "Sign or verify the site policy that bounds admitted workload authority.\n\nUsage: stewardctl policy sign|verify ...\n",
	"keygen":           "Create an Ed25519 signing key pair in owner-only files.\n\nUsage: stewardctl keygen -private-out FILE -public-out FILE [-key-id ID]\n",
	"key":              "Check that one private key matches one public key.\n\nUsage: stewardctl key match -private-key FILE -public-key FILE\n",
	"completion":       "Install or print local shell completion.\n\nUsage: stewardctl completion install|bash|zsh|fish\n",
	"upgrade":          "Inspect whether a node is drained and whether retained formats are compatible with an upgrade.\n\nUsage: stewardctl upgrade check-drained|inspect-formats ...\n",
	"executor-command": "Issue or verify a signed command or bounded controller delegation delivered to Executor. This is an advanced transport tool; routine fleet operations use stewardctl control.\n\nUsage: stewardctl executor-command issue|verify|delegation ...\n",
}

func nodeCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("node command requires whoami, admit, status, logs, egress, start, stop, destroy, snapshot-state, clone-state, delete-snapshot, purge-state, or maintenance")
	}
	var err error
	arguments, err = applyNodeCLIContext(arguments)
	if err != nil {
		return err
	}
	if len(arguments) == 0 {
		return errors.New("node command requires a subcommand after -no-context")
	}
	if arguments[0] == "maintenance" {
		return nodeMaintenanceCommand(arguments[1:], stdout)
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
	instanceID := flags.String("instance-id", "", "signed instance identity")
	snapshotID := flags.String("snapshot-id", "", "immutable state snapshot identity")
	sourceLineageID := flags.String("source-lineage-id", "", "source state lineage identity")
	generation := flags.Uint64("generation", 0, "signed instance generation")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if *tokenFile == "" {
		return errors.New("node command requires -token-file or a context containing one")
	}
	positional := flags.Args()
	client, err := nodeclient.NewFromTokenFile(*nodeURL, *tokenFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var result any
	switch action {
	case "whoami":
		if len(positional) != 0 || *runtimeRef != "" || *capsulePath != "" || *intentPath != "" || *tenantID != "" ||
			*nodeID != "" || *lineageID != "" || *instanceID != "" || *snapshotID != "" || *sourceLineageID != "" || *generation != 0 {
			return errors.New("node whoami accepts only connection flags")
		}
		result, err = client.LocalPrincipal(ctx)
		if err != nil {
			return err
		}
	case "admit":
		if len(positional) != 0 || *capsulePath == "" || *intentPath == "" || *runtimeRef != "" {
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
		selectedRuntimeRef := *runtimeRef
		if len(positional) == 1 && selectedRuntimeRef == "" {
			selectedRuntimeRef = positional[0]
		} else if len(positional) != 0 {
			return fmt.Errorf("node %s accepts one runtime reference, either positionally or with -runtime-ref", action)
		}
		if selectedRuntimeRef == "" || *capsulePath != "" || *intentPath != "" {
			return fmt.Errorf("node %s requires one runtime reference", action)
		}
		switch action {
		case "status":
			result, err = client.Status(ctx, selectedRuntimeRef)
		case "logs":
			result, err = client.Logs(ctx, selectedRuntimeRef)
		case "egress":
			result, err = client.EgressStats(ctx, selectedRuntimeRef)
		case "start":
			result, err = client.Start(ctx, selectedRuntimeRef)
		case "stop":
			result, err = client.Stop(ctx, selectedRuntimeRef)
		case "destroy":
			err = client.Destroy(ctx, selectedRuntimeRef)
			result = map[string]any{"runtime_ref": selectedRuntimeRef, "destroyed": err == nil}
		}
		if err != nil {
			return err
		}
	case "purge-state":
		if len(positional) != 0 || *tenantID == "" || *nodeID == "" || *lineageID == "" || *generation == 0 ||
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
	case "snapshot-state":
		if len(positional) != 0 || *tenantID == "" || *nodeID == "" || *instanceID == "" ||
			*lineageID == "" || *snapshotID == "" || *generation == 0 || *sourceLineageID != "" ||
			*runtimeRef != "" || *capsulePath != "" || *intentPath != "" {
			return errors.New("node snapshot-state requires -tenant-id, -node-id, -instance-id, -lineage-id, -generation, and -snapshot-id")
		}
		result, err = client.SnapshotState(ctx, nodeclient.StateSnapshotRequest{
			TenantID: *tenantID, NodeID: *nodeID, InstanceID: *instanceID,
			LineageID: *lineageID, Generation: *generation, SnapshotID: *snapshotID,
		})
		if err != nil {
			return err
		}
	case "clone-state":
		if len(positional) != 0 || *tenantID == "" || *nodeID == "" || *instanceID == "" ||
			*lineageID == "" || *sourceLineageID == "" || *snapshotID == "" || *generation == 0 ||
			*runtimeRef != "" || *capsulePath != "" || *intentPath != "" {
			return errors.New("node clone-state requires -tenant-id, -node-id, -instance-id, -lineage-id, -generation, -snapshot-id, and -source-lineage-id")
		}
		result, err = client.CloneState(ctx, nodeclient.StateCloneRequest{
			TenantID: *tenantID, NodeID: *nodeID, InstanceID: *instanceID,
			LineageID: *lineageID, Generation: *generation, SnapshotID: *snapshotID,
			SourceLineageID: *sourceLineageID,
		})
		if err != nil {
			return err
		}
	case "delete-snapshot":
		if len(positional) != 0 || *tenantID == "" || *nodeID == "" || *instanceID == "" ||
			*lineageID == "" || *snapshotID == "" || *generation == 0 || *sourceLineageID != "" ||
			*runtimeRef != "" || *capsulePath != "" || *intentPath != "" {
			return errors.New("node delete-snapshot requires -tenant-id, -node-id, -instance-id, -lineage-id, -generation, and -snapshot-id")
		}
		err = client.DeleteStateSnapshot(ctx, nodeclient.StateSnapshotRequest{
			TenantID: *tenantID, NodeID: *nodeID, InstanceID: *instanceID,
			LineageID: *lineageID, Generation: *generation, SnapshotID: *snapshotID,
		})
		result = map[string]any{"tenant_id": *tenantID, "snapshot_id": *snapshotID, "deleted": err == nil}
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

func capsuleCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) > 0 && arguments[0] == "check-profile" {
		flags := flag.NewFlagSet("capsule check-profile", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		input := flags.String("in", "", "strict capsule JSON payload")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if *input == "" || flags.NArg() != 0 {
			return errors.New("capsule check-profile requires -in")
		}
		raw, err := readBounded(*input)
		if err != nil {
			return err
		}
		var capsule admission.ProfileCapsule
		if err := dsse.DecodeStrictInto(raw, maxArtifactBytes, &capsule); err != nil {
			return err
		}
		if err := capsule.Validate(timeNow()); err != nil {
			return err
		}
		profile, err := admission.ValidateProfileContract(capsule, admission.DefaultProfiles())
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]any{
			"valid": true, "profile": profile.Ref, "uid": profile.UID, "gid": profile.GID,
			"state_path": profile.StatePath, "command": capsule.Command, "service": capsule.Service,
		})
	}
	return artifact(arguments, stdout, admission.CapsulePayloadType)
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
		if err := capsule.Validate(timeNow()); err != nil {
			return err
		}
		_, err := admission.ValidateProfileContract(capsule, admission.DefaultProfiles())
		return err
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
	case admission.CommandDelegationPayloadType:
		var delegation admission.CommandDelegation
		if err := dsse.DecodeStrictInto(payload, maxArtifactBytes, &delegation); err != nil {
			return err
		}
		return delegation.Validate(timeNow())
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
	return decodePrivateKey(raw)
}

func decodePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
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
	return decodePublicKey(raw)
}

func decodePublicKey(raw []byte) (ed25519.PublicKey, error) {
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
