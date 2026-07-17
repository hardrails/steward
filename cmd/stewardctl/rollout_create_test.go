package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutstore"
)

func TestRolloutCreateBuildsOwnerOnlyResumableWorkspace(t *testing.T) {
	fixture := newOfflineActivationFixture(t)
	inputDirectory := t.TempDir()
	_, commandPublicPath := generateTestKeyPair(t, inputDirectory, "rollout-command")
	commandPublic, err := readPublicKey(commandPublicPath)
	if err != nil {
		t.Fatal(err)
	}

	policyEnvelopeRaw := offlineRead(
		t, filepath.Join(fixture.directory, activationstore.PolicyFileName),
	)
	policyEnvelope, err := dsse.Parse(policyEnvelopeRaw)
	if err != nil {
		t.Fatal(err)
	}
	policyPayload, err := base64.StdEncoding.DecodeString(policyEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var policy admission.SitePolicy
	if err := json.Unmarshal(policyPayload, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Tenants[0].CommandKeys = []admission.CommandKey{{
		KeyID:      "rollout-command",
		PublicKey:  base64.StdEncoding.EncodeToString(commandPublic),
		Operations: []string{"admit", "start", "activation-canary"},
	}}
	sitePrivatePath := strings.TrimSuffix(fixture.siteRootPublicPath, ".public") + ".private.pem"
	sitePrivate, err := readPrivateKey(sitePrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(inputDirectory, "policy.dsse.json")
	writeSignedJSON(
		t, policyPath, admission.PolicyPayloadType, policy, "site-root", sitePrivate,
	)

	copyInput := func(name, source string) string {
		t.Helper()
		raw := offlineRead(t, source)
		path := filepath.Join(inputDirectory, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return name
	}
	intentName := copyInput(
		"intent.json", filepath.Join(fixture.directory, activationstore.IntentFileName),
	)
	serviceTrustName := copyInput(
		"service-trust.json",
		filepath.Join(fixture.directory, activationstore.ServiceTrustFileName),
	)
	gatewayKeyName := copyInput("gateway.public", fixture.gatewayPublicPath)
	inputsRaw, err := json.Marshal(rolloutInputsV1{
		SchemaVersion: rolloutInputsSchemaV1,
		Targets: []rolloutTargetInputV1{{
			IntentFile:                  intentName,
			ServiceTrustFile:            serviceTrustName,
			GatewayReceiptPublicKeyFile: gatewayKeyName,
			GatewayReceiptEpoch:         1,
			ClaimGeneration:             1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	inputsPath := filepath.Join(inputDirectory, "targets.json")
	if err := os.WriteFile(inputsPath, inputsRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	workspace := filepath.Join(t.TempDir(), "rollout")
	var output bytes.Buffer
	if err := rolloutCommand([]string{
		"create",
		"-dir", workspace,
		"-rollout-id", "rollout-create-test",
		"-release", filepath.Join(fixture.directory, activationstore.ReleaseFileName),
		"-policy", policyPath,
		"-archive", filepath.Join(fixture.directory, activationstore.ImageArchiveFileName),
		"-targets", inputsPath,
		"-publisher-public-key", fixture.publisherPublicPath,
		"-publisher-key-id", "publisher-a",
		"-site-root-public-key", fixture.siteRootPublicPath,
		"-site-root-key-id", "site-root",
		"-witness-public-key", fixture.witnessPublicPath,
		"-valid-for", "5m",
		"-json",
	}, &output); err != nil {
		t.Fatal(err)
	}
	var status rolloutStatusOutput
	if err := json.Unmarshal(output.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.RolloutID != "rollout-create-test" ||
		status.Phase != rollout.FleetPhaseRunning ||
		status.CurrentPhase != rollout.PhasePlanned ||
		status.TotalTargets != 1 || status.PassedTargets != 0 || status.Verified {
		t.Fatalf("created rollout status=%#v", status)
	}

	info, err := os.Stat(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("rollout workspace mode=%#o, want 0700", info.Mode().Perm())
	}
	store, err := rolloutstore.Open(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	planRaw, err := store.Read(rolloutstore.PlanFileName, rollout.MaxPlanBytes)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := rollout.ParsePlanV1(planRaw)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RolloutID != "rollout-create-test" || len(plan.Targets) != 1 ||
		plan.Targets[0].NodeID != "node-a" || plan.Targets[0].ActivationID == "" {
		t.Fatalf("created rollout plan=%#v", plan)
	}
	states, err := store.ListTargetStates(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || !strings.HasSuffix(states[0], "000000000000.json") {
		t.Fatalf("created rollout states=%#v", states)
	}
	deadline, err := time.Parse(time.RFC3339Nano, plan.Deadline)
	if err != nil || !deadline.Equal(fixture.now.Add(5*time.Minute)) {
		t.Fatalf("created rollout deadline=%q: %v", plan.Deadline, err)
	}
}

func TestParseRolloutInputsV1RejectsAmbiguousOrEscapingManifests(t *testing.T) {
	valid := []byte(`{"schema_version":"steward.rollout-inputs.v1","targets":[{"intent_file":"intent.json","service_trust_file":"service.json","gateway_receipt_public_key_file":"gateway.public","gateway_receipt_epoch":1,"claim_generation":2}]}`)
	inputs, err := parseRolloutInputsV1(valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs.Targets) != 1 || inputs.Targets[0].IntentFile != "intent.json" {
		t.Fatalf("parsed rollout inputs=%#v", inputs)
	}

	for name, raw := range map[string][]byte{
		"unknown field": []byte(`{"schema_version":"steward.rollout-inputs.v1","targets":[{"intent_file":"intent.json","service_trust_file":"service.json","gateway_receipt_public_key_file":"gateway.public","gateway_receipt_epoch":1,"claim_generation":2,"selector":"all"}]}`),
		"parent escape": bytes.Replace(valid, []byte(`"intent.json"`), []byte(`"../intent.json"`), 1),
		"nested path":   bytes.Replace(valid, []byte(`"service.json"`), []byte(`"nested/service.json"`), 1),
		"absolute path": bytes.Replace(
			valid, []byte(`"gateway.public"`), []byte(`"/tmp/gateway.public"`), 1,
		),
		"zero epoch": bytes.Replace(valid, []byte(`"gateway_receipt_epoch":1`), []byte(`"gateway_receipt_epoch":0`), 1),
		"zero claim": bytes.Replace(valid, []byte(`"claim_generation":2`), []byte(`"claim_generation":0`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRolloutInputsV1(raw); err == nil {
				t.Fatal("unsafe rollout input manifest was accepted")
			}
		})
	}
}

func TestReadRolloutInputCompanionUsesAnchoredDirectory(t *testing.T) {
	parent := t.TempDir()
	requested := filepath.Join(parent, "inputs")
	if err := os.Mkdir(requested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(requested, "intent.json"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(requested)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	moved := filepath.Join(parent, "inputs-moved")
	if err := os.Rename(requested, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(requested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(requested, "intent.json"), []byte("substituted"), 0o644); err != nil {
		t.Fatal(err)
	}

	raw, err := readRolloutInputCompanion(root, "intent.json", 64)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "original" {
		t.Fatalf("anchored companion=%q, want original bytes", raw)
	}
}

func TestParseRolloutBase64PublicKeyUsesExactSnapshot(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(base64.StdEncoding.EncodeToString(public) + "\n")
	parsed, err := parseRolloutBase64PublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, public) {
		t.Fatal("parsed rollout public key changed bytes")
	}
	parsed[0] ^= 0xff
	parsedAgain, err := parseRolloutBase64PublicKey(raw)
	if err != nil || !bytes.Equal(parsedAgain, public) {
		t.Fatalf("parsed rollout key aliases its source: %v", err)
	}
	if _, err := parseRolloutBase64PublicKey([]byte(base64.RawStdEncoding.EncodeToString(public))); err == nil {
		t.Fatal("non-canonical unpadded rollout public key was accepted")
	}
	if _, err := parseRolloutBase64PublicKey(append([]byte(" "), raw...)); err == nil {
		t.Fatal("whitespace-prefixed rollout public key was accepted")
	}
}

func TestRolloutEvidenceCaptureTTLIsDeterministicAndBounded(t *testing.T) {
	timeouts := activation.TimeoutsV1{
		AdmissionSeconds: 120,
		StartupSeconds:   300,
		CanarySeconds:    300,
		EvidenceSeconds:  120,
	}
	got, err := rolloutEvidenceCaptureTTL(timeouts)
	if err != nil || got != 14*time.Minute {
		t.Fatalf("capture TTL=%s error=%v, want 14m", got, err)
	}

	timeouts.EvidenceSeconds = 24 * 60 * 60
	if _, err := rolloutEvidenceCaptureTTL(timeouts); err == nil ||
		!strings.Contains(err.Error(), "one bounded controller evidence capture") {
		t.Fatalf("oversized capture timeout error=%v", err)
	}
}

func TestRolloutCommandDispatchesCreateAndStatus(t *testing.T) {
	if err := rolloutCommand(nil, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "create or status") {
		t.Fatalf("empty rollout command error=%v", err)
	}
	if err := rolloutCommand([]string{"create"}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "rollout create requires") {
		t.Fatalf("create dispatch error=%v", err)
	}
	if err := rolloutCommand([]string{"status"}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "rollout status requires") {
		t.Fatalf("status dispatch error=%v", err)
	}
}
