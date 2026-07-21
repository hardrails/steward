package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/gateway"
)

func TestGatewayEffectsCheckProvesExactReadinessWithoutDisclosingSecrets(t *testing.T) {
	fixture := newGatewayEffectsFixture(t)
	before := snapshotGatewayEffectsFixture(t, fixture.directory)
	var output bytes.Buffer
	if err := run(fixture.arguments(), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	after := snapshotGatewayEffectsFixture(t, fixture.directory)
	if len(before) != len(after) {
		t.Fatalf("read-only check changed fixture entries: before=%d after=%d", len(before), len(after))
	}
	for path, value := range before {
		if after[path] != value {
			t.Fatalf("read-only check changed %q", path)
		}
	}
	if output.Len() == 0 || output.Len() > maxGatewayEffectsCheckOutputBytes {
		t.Fatalf("readiness output length = %d", output.Len())
	}
	var summary gatewayEffectsCheckSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Status != "ready" || summary.EffectMode != admission.EffectModeAuthorized ||
		summary.TenantID != fixture.intent.TenantID || summary.NodeID != fixture.intent.NodeID ||
		!slices.Equal(summary.ConnectorIDs, []string{"mail", "vault"}) ||
		!slices.Equal(summary.KeyIDs, []string{"approver-a", "approver-b"}) ||
		summary.MinApprovals != 1 ||
		summary.ReceiptBudgetBytes != 1<<20 {
		t.Fatalf("readiness summary = %#v", summary)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	if len(members) != 8 {
		t.Fatalf("readiness summary exposed unexpected members: %s", output.String())
	}
	for _, forbidden := range append([]string{
		"base_url", "credential", "public_key", "operation", "path",
	}, fixture.secrets...) {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("readiness summary disclosed %q: %s", forbidden, output.String())
		}
	}
}

func TestGatewayEffectsCheckFailsClosedOnAuthorityAndIsolationMismatch(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*testing.T, *gatewayEffectsFixture)
	}{
		{
			name: "standard effect mode", want: "explicitly select authorized",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.intent.EffectMode = admission.EffectModeStandard
			},
		},
		{
			name: "generic egress capability", want: "forbids generic egress",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.intent.Capabilities.Egress = true
			},
		},
		{
			name: "generic egress route", want: "forbids generic egress",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.intent.EgressRouteIDs = []string{"internet"}
			},
		},
		{
			name: "connector capability omitted", want: "requires connector capability",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.intent.Capabilities.Connector = false
			},
		},
		{
			name: "connector selection omitted", want: "at least one selected connector",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.intent.ConnectorIDs = nil
			},
		},
		{
			name: "duplicate connector selection", want: "duplicate selected authorized effects connector",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.intent.ConnectorIDs = []string{"mail", "mail"}
			},
		},
		{
			name: "node mismatch", want: "action-permit node does not match",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.config.ActionPermitNodeID = "node-b"
			},
		},
		{
			name: "authority tenant mismatch", want: "does not exactly match signed tenant policy",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.config.ActionAuthorities[0].TenantID = "tenant-b"
			},
		},
		{
			name: "authority public key mismatch", want: "does not exactly match signed tenant policy",
			mutate: func(t *testing.T, fixture *gatewayEffectsFixture) {
				fixture.config.ActionAuthorities[0].PublicKey = generatedPublicKey(t)
			},
		},
		{
			name: "authority key ID mismatch", want: "does not exactly match signed tenant policy",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.config.ActionAuthorities[0].KeyID = "approver-c"
				fixture.config.Connectors[0].ActionAuthorityIDs = []string{"approver-c"}
				fixture.config.Connectors[1].ActionAuthorityIDs = []string{"approver-b", "approver-c"}
			},
		},
		{
			name: "connector authority widening", want: "action-authority scope does not exactly match",
			mutate: func(t *testing.T, fixture *gatewayEffectsFixture) {
				fixture.config.ActionAuthorities = append(fixture.config.ActionAuthorities, gateway.ActionAuthority{
					KeyID: "approver-z", TenantID: fixture.intent.TenantID, PublicKey: generatedPublicKey(t),
				})
				fixture.config.Connectors[0].ActionAuthorityIDs = []string{"approver-a", "approver-z"}
			},
		},
		{
			name: "selected connector absent from Gateway", want: "does not configure selected connector",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.intent.ConnectorIDs = []string{"other"}
				tenant := &fixture.policy.Tenants[0]
				tenant.ConnectorIDs = []string{"mail", "other", "vault"}
				tenant.AuthorizedEffects.Keys[0].ConnectorIDs = []string{"mail", "other", "vault"}
			},
		},
		{
			name: "signed policy key ID mismatch", want: "does not exactly match signed tenant policy",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.policy.Tenants[0].AuthorizedEffects.Keys[0].KeyID = "approver-c"
			},
		},
		{
			name: "signed policy public key mismatch", want: "does not exactly match signed tenant policy",
			mutate: func(t *testing.T, fixture *gatewayEffectsFixture) {
				fixture.policy.Tenants[0].AuthorizedEffects.Keys[0].PublicKey = generatedPublicKey(t)
			},
		},
		{
			name: "tenant receipt budget absent", want: "no durable connector receipt budget",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.config.ConnectorReceiptTenantBudgets[0].TenantID = "tenant-b"
			},
		},
		{
			name: "signed tenant policy absent", want: "tenant has no authorized effects policy",
			mutate: func(_ *testing.T, fixture *gatewayEffectsFixture) {
				fixture.policy.Tenants[0].AuthorizedEffects = nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayEffectsFixture(t)
			test.mutate(t, fixture)
			fixture.writeInputs(t)
			err := run(fixture.arguments(), &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("gateway effects check error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestGatewayEffectsCheckRejectsMalformedArtifactsAndAmbiguousCLI(t *testing.T) {
	fixture := newGatewayEffectsFixture(t)
	validArguments := fixture.arguments()

	for _, flagName := range []string{"-config", "-intent", "-policy", "-site-root-public-key", "-site-root-key-id"} {
		t.Run("missing "+flagName, func(t *testing.T) {
			arguments := removeFlagPair(validArguments, flagName)
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatalf("missing flag %s was accepted", flagName)
			}
		})
	}
	for _, arguments := range [][]string{
		{"gateway", "effects"},
		{"gateway", "effects", "unknown"},
		append(append([]string(nil), validArguments...), "extra"),
		append(append([]string(nil), validArguments...), "-intent", fixture.intentPath),
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("ambiguous effects command accepted: %#v", arguments)
		}
	}

	t.Run("unknown intent field", func(t *testing.T) {
		candidate := newGatewayEffectsFixture(t)
		raw, err := json.Marshal(candidate.intent)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...)
		if err := os.WriteFile(candidate.intentPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		err = run(candidate.arguments(), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "unknown JSON field") {
			t.Fatalf("unknown intent field error = %v", err)
		}
	})

	t.Run("duplicate intent field", func(t *testing.T) {
		candidate := newGatewayEffectsFixture(t)
		raw, err := os.ReadFile(candidate.intentPath)
		if err != nil {
			t.Fatal(err)
		}
		raw = bytes.Replace(raw, []byte(`"effect_mode":"authorized"`),
			[]byte(`"effect_mode":"authorized","effect_mode":"authorized"`), 1)
		if err := os.WriteFile(candidate.intentPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		err = run(candidate.arguments(), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
			t.Fatalf("duplicate intent field error = %v", err)
		}
	})

	t.Run("untrusted site policy", func(t *testing.T) {
		candidate := newGatewayEffectsFixture(t)
		_, otherPublic := generateTestKeyPair(t, candidate.directory, "other-site-root")
		candidate.siteRootPublicPath = otherPublic
		err := run(candidate.arguments(), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "verify site policy") {
			t.Fatalf("untrusted policy error = %v", err)
		}
	})

	t.Run("invalid Gateway config", func(t *testing.T) {
		candidate := newGatewayEffectsFixture(t)
		if err := os.WriteFile(candidate.configPath, []byte(`{"version":1,"unexpected":true}`), 0o640); err != nil {
			t.Fatal(err)
		}
		err := run(candidate.arguments(), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "decode gateway config") {
			t.Fatalf("invalid Gateway config error = %v", err)
		}
	})

	for _, input := range []struct {
		name string
		path func(*gatewayEffectsFixture) string
	}{
		{name: "writable intent", path: func(fixture *gatewayEffectsFixture) string { return fixture.intentPath }},
		{name: "writable policy", path: func(fixture *gatewayEffectsFixture) string { return fixture.policyPath }},
	} {
		t.Run(input.name, func(t *testing.T) {
			candidate := newGatewayEffectsFixture(t)
			if err := os.Chmod(input.path(candidate), 0o666); err != nil {
				t.Fatal(err)
			}
			if err := run(candidate.arguments(), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("readiness check accepted an operator-writable trust input")
			}
		})
	}

	t.Run("invalid retained Gateway state", func(t *testing.T) {
		candidate := newGatewayEffectsFixture(t)
		if err := os.WriteFile(candidate.config.StateFile, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		err := run(candidate.arguments(), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "validate Gateway configuration") ||
			!strings.Contains(err.Error(), "gateway state is invalid") {
			t.Fatalf("invalid Gateway state error = %v", err)
		}
	})

	var usageOutput bytes.Buffer
	if err := run([]string{"help", "gateway"}, &usageOutput, &bytes.Buffer{}); err != nil ||
		!strings.Contains(usageOutput.String(), "stewardctl gateway validate|identity|inference|route|connector|service|effects") {
		t.Fatalf("gateway help = %q error = %v", usageOutput.String(), err)
	}
}

type gatewayEffectsFixture struct {
	directory          string
	configPath         string
	intentPath         string
	policyPath         string
	siteRootPublicPath string
	siteRootPrivate    ed25519.PrivateKey
	config             gateway.Config
	intent             admission.InstanceIntent
	policy             admission.SitePolicy
	secrets            []string
}

func newGatewayEffectsFixture(t *testing.T) *gatewayEffectsFixture {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "steward-effects-check-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })

	siteRootPrivatePath, siteRootPublicPath := generateTestKeyPair(t, directory, "site-root")
	siteRootPrivate, err := readPrivateKey(siteRootPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	_, actionAPublicPath := generateTestKeyPair(t, directory, "action-a")
	actionAPublic, err := readPublicKey(actionAPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	_, actionBPublicPath := generateTestKeyPair(t, directory, "action-b")
	actionBPublic, err := readPublicKey(actionBPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	publisherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptPrivatePath, _ := generateTestKeyPair(t, directory, "receipt")

	tokenPath := filepath.Join(directory, "gateway.token")
	mailCredentialPath := filepath.Join(directory, "mail.credential")
	vaultCredentialPath := filepath.Join(directory, "vault.credential")
	if err := os.WriteFile(tokenPath, []byte("gateway-service-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		mailCredentialPath:  "mail-upstream-secret",
		vaultCredentialPath: "vault-upstream-secret",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gid := os.Getgid()
	if gid == 0 {
		gid = 1
	}
	actionAPublicText := base64.StdEncoding.EncodeToString(actionAPublic)
	actionBPublicText := base64.StdEncoding.EncodeToString(actionBPublic)
	siteRootPublicRaw, err := os.ReadFile(siteRootPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "gateway.json")
	intentPath := filepath.Join(directory, "intent.json")
	policyPath := filepath.Join(directory, "policy.dsse.json")
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: tokenPath, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: gid, RelayGID: gid, ActionPermitNodeID: "node-a",
		ActionAuthorities: []gateway.ActionAuthority{
			{KeyID: "approver-a", TenantID: "tenant-a", PublicKey: actionAPublicText},
			{KeyID: "approver-b", TenantID: "tenant-a", PublicKey: actionBPublicText},
		},
		Connectors: []gateway.Connector{
			{
				ID: "mail", BaseURL: "https://mail-sensitive.example.test", CredentialFile: mailCredentialPath,
				CredentialMode: gateway.CredentialModeBearer, CredentialEpoch: 4,
				MaxConcurrent: 2, MaxRequestBytes: 64 << 10, MaxResponseBytes: 64 << 10, MaxSeconds: 30,
				MaxCallsPerGrant: 8, ActionAuthorityIDs: []string{"approver-a"}, MaxActionPermitSeconds: 300,
				Operations: []gateway.ConnectorOperation{{ID: "send", Method: "POST", Path: "/v1/private/send"}},
			},
			{
				ID: "vault", BaseURL: "https://vault-sensitive.example.test", CredentialFile: vaultCredentialPath,
				CredentialMode: gateway.CredentialModeXAPIKey, CredentialEpoch: 9,
				MaxConcurrent: 1, MaxRequestBytes: 32 << 10, MaxResponseBytes: 32 << 10, MaxSeconds: 20,
				MaxCallsPerGrant: 4, ActionAuthorityIDs: []string{"approver-a", "approver-b"}, MaxActionPermitSeconds: 120,
				Operations: []gateway.ConnectorOperation{{ID: "rotate", Method: "POST", Path: "/v1/private/rotate"}},
			},
		},
		ConnectorReceiptFile: filepath.Join(directory, "receipts.ndjson"), ConnectorReceiptKeyFile: receiptPrivatePath,
		ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 1,
		ConnectorReceiptTenantBudgets: []gateway.ConnectorReceiptTenantBudget{{TenantID: "tenant-a", Bytes: 1 << 20}},
	}
	ceiling := admission.ResourceLimits{MemoryBytes: 1 << 30, CPUMillis: 2000, PIDs: 256}
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1, PolicyID: "site-a", PolicyEpoch: 1,
		Publishers: []admission.PublisherRule{{
			KeyID: "publisher-a", PublicKey: base64.StdEncoding.EncodeToString(publisherPublic),
			AllowedProfiles:     []admission.ProfileRef{{ID: "generic-v1", Version: "v1"}},
			AllowedRepositories: []string{"registry.example/agent"}, ResourceCeiling: ceiling,
		}},
		Tenants: []admission.TenantRule{{
			TenantID: "tenant-a", PublisherKeyIDs: []string{"publisher-a"}, ResourceCeiling: ceiling,
			ConnectorIDs: []string{"mail", "vault"},
			AuthorizedEffects: &admission.AuthorizedEffectsPolicy{
				Mode: admission.AuthorizedEffectsRequired,
				Keys: []admission.ActionKey{
					{KeyID: "approver-a", PublicKey: actionAPublicText, ConnectorIDs: []string{"mail", "vault"}},
					{KeyID: "approver-b", PublicKey: actionBPublicText, ConnectorIDs: []string{"vault"}},
				},
			},
		}},
	}
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a", LineageID: "lineage-a", Generation: 1,
		CapsuleDigest: "sha256:" + strings.Repeat("a", 64),
		Resources:     admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		Capabilities:  admission.Capabilities{Connector: true}, StateDisposition: "none",
		ConnectorIDs: []string{"vault", "mail"}, EffectMode: admission.EffectModeAuthorized,
	}
	fixture := &gatewayEffectsFixture{
		directory: directory, configPath: configPath, intentPath: intentPath,
		policyPath: policyPath, siteRootPublicPath: siteRootPublicPath,
		siteRootPrivate: siteRootPrivate, config: config, intent: intent, policy: policy,
		secrets: []string{
			"mail-sensitive.example.test", "vault-sensitive.example.test", "mail-upstream-secret", "vault-upstream-secret",
			mailCredentialPath, vaultCredentialPath, "/v1/private/send", "/v1/private/rotate", actionAPublicText, actionBPublicText,
			"gateway-service-token", tokenPath, receiptPrivatePath, configPath, intentPath, policyPath,
			strings.TrimSpace(string(siteRootPublicRaw)),
		},
	}
	fixture.writeInputs(t)
	return fixture
}

func (fixture *gatewayEffectsFixture) writeInputs(t *testing.T) {
	t.Helper()
	writeGatewayEffectsJSON(t, fixture.configPath, fixture.config, 0o640)
	writeGatewayEffectsJSON(t, fixture.intentPath, fixture.intent, 0o600)
	writeSignedJSON(t, fixture.policyPath, admission.PolicyPayloadType, fixture.policy, "site-root", fixture.siteRootPrivate)
}

func (fixture *gatewayEffectsFixture) arguments() []string {
	return []string{
		"gateway", "effects", "check", "-config", fixture.configPath, "-intent", fixture.intentPath,
		"-policy", fixture.policyPath, "-site-root-public-key", fixture.siteRootPublicPath, "-site-root-key-id", "site-root",
	}
}

func writeGatewayEffectsJSON(t *testing.T, path string, value any, mode os.FileMode) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
}

func generatedPublicKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(public)
}

func removeFlagPair(arguments []string, flagName string) []string {
	result := make([]string, 0, len(arguments)-2)
	for index := 0; index < len(arguments); index++ {
		if arguments[index] == flagName && index+1 < len(arguments) {
			index++
			continue
		}
		result = append(result, arguments[index])
	}
	return result
}

func snapshotGatewayEffectsFixture(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			snapshot[relative+string(filepath.Separator)] = "directory"
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snapshot[relative] = info.Mode().String() + "\x00" + string(raw)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}
