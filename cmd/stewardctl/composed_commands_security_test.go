package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/gateway"
)

func TestComposedAgentCommandsRejectIncompleteAndConflictingInputs(t *testing.T) {
	for name, runCase := range map[string]func() error{
		"publish missing arguments": func() error {
			return agentCommand([]string{"publish"}, &bytes.Buffer{})
		},
		"publish unknown flag": func() error {
			return agentCommand([]string{"publish", "-unknown"}, &bytes.Buffer{})
		},
		"publish missing site": func() error {
			return agentCommand([]string{"publish", t.TempDir(), "-archive", "missing.tar"}, &bytes.Buffer{})
		},
		"authorize missing arguments": func() error {
			return agentCommand([]string{"authorize"}, &bytes.Buffer{})
		},
		"authorize unknown flag": func() error {
			return agentCommand([]string{"authorize", "-unknown"}, &bytes.Buffer{})
		},
		"authorize invalid node": func() error {
			return agentCommand([]string{"authorize", t.TempDir(), "-node-ids", "not a node"}, &bytes.Buffer{})
		},
		"service missing subcommand": func() error {
			return agentCommand([]string{"service"}, &bytes.Buffer{})
		},
		"service unknown subcommand": func() error {
			return agentCommand([]string{"service", "replace"}, &bytes.Buffer{})
		},
		"service unknown flag": func() error {
			return agentCommand([]string{"service", "activate", "-unknown"}, &bytes.Buffer{})
		},
		"service missing identities": func() error {
			return agentCommand([]string{"service", "activate"}, &bytes.Buffer{})
		},
		"service invalid budget": func() error {
			return agentCommand([]string{"service", "activate", "-tenant-id", "tenant-a", "-node-id", "node-a", "-tenant-budget-bytes", "1"}, &bytes.Buffer{})
		},
		"service missing bundle": func() error {
			return agentCommand([]string{"service", "activate", "-tenant-id", "tenant-a", "-node-id", "node-a", "-bundle", "missing.json"}, &bytes.Buffer{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runCase(); err == nil {
				t.Fatal("unsafe input was accepted")
			}
		})
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	siteDirectory := filepath.Join(directory, "site")
	if err := siteCommand([]string{"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	verified, err := verifySitePackage(siteDirectory, "")
	if err != nil {
		t.Fatal(err)
	}
	_, unrelated, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSitePublisherKey(verified.policy, unrelated); err == nil {
		t.Fatal("unrelated publisher key was accepted")
	}
	if err := validateGeneratedTenantCommandKey(verified.policy, unrelated); err == nil {
		t.Fatal("unrelated tenant command key was accepted")
	}
	if _, ok := agentPublicationContractFor("unsupported"); ok {
		t.Fatal("unsupported runtime received a publication contract")
	}
	template := agentDelegationTemplate(admission.InstanceIntent{}, agentapp.Placement{
		RequiredLabels:  []agentapp.Label{{Key: "zone", Value: "b"}, {Key: "arch", Value: "a"}},
		PreferredLabels: []agentapp.Label{{Key: "rack", Value: "b"}, {Key: "rack", Value: "a"}},
		Tolerations:     []string{"gpu", "batch"},
	})
	if len(template.Placement.RequiredLabels) != 2 || len(template.Placement.PreferredLabels) != 2 ||
		!slices.Equal(template.Placement.Tolerations, []string{"batch", "gpu"}) {
		t.Fatalf("derived placement template = %+v", template.Placement)
	}
	archive, manifestDigest, _, _ := writeImageImportArchive(t, directory)
	bundle := publishedAgentBundle(t, "openclaw", "steward.local/agents@"+manifestDigest)
	bundleRaw, err := agentapp.MarshalCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(directory, "agent.bundle.json")
	if err := os.WriteFile(bundlePath, bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	capsulePath := filepath.Join(directory, "capsule.dsse.json")
	if err := agentCommand([]string{
		"publish", siteDirectory, "-bundle", bundlePath, "-archive", archive, "-out", capsulePath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	invalidBundle := filepath.Join(directory, "invalid.bundle.json")
	if err := os.WriteFile(invalidBundle, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manyNodes := make([]string, 65)
	for index := range manyNodes {
		manyNodes[index] = "node-" + strconv.Itoa(index)
	}
	for name, arguments := range map[string][]string{
		"publish missing bundle":       {"publish", siteDirectory, "-bundle", filepath.Join(directory, "missing"), "-archive", archive},
		"publish invalid bundle":       {"publish", siteDirectory, "-bundle", invalidBundle, "-archive", archive},
		"publish invalid archive":      {"publish", siteDirectory, "-bundle", bundlePath, "-archive", invalidBundle},
		"publish existing output":      {"publish", siteDirectory, "-bundle", bundlePath, "-archive", archive, "-out", capsulePath},
		"authorize duplicate node":     {"authorize", siteDirectory, "-bundle", bundlePath, "-capsule", capsulePath, "-node-ids", "node-a,node-a"},
		"authorize too many nodes":     {"authorize", siteDirectory, "-bundle", bundlePath, "-capsule", capsulePath, "-node-ids", strings.Join(manyNodes, ",")},
		"authorize missing bundle":     {"authorize", siteDirectory, "-bundle", "missing", "-capsule", capsulePath, "-node-ids", "node-a"},
		"authorize invalid bundle":     {"authorize", siteDirectory, "-bundle", invalidBundle, "-capsule", capsulePath, "-node-ids", "node-a"},
		"authorize missing capsule":    {"authorize", siteDirectory, "-bundle", bundlePath, "-capsule", "missing", "-node-ids", "node-a"},
		"authorize missing controller": {"authorize", siteDirectory, "-bundle", bundlePath, "-capsule", capsulePath, "-controller-public-key", "missing", "-node-ids", "node-a"},
		"service invalid bundle":       {"service", "activate", "-bundle", invalidBundle, "-tenant-id", "tenant-a", "-node-id", "node-a"},
		"service missing config":       {"service", "activate", "-bundle", bundlePath, "-config", filepath.Join(directory, "missing-gateway.json"), "-tenant-id", "tenant-a", "-node-id", "node-a"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := agentCommand(arguments, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe composed agent input was accepted")
			}
		})
	}
	if compared := compareDelegationLabels(
		admission.CommandDelegationLabel{Key: "a", Value: "z"},
		admission.CommandDelegationLabel{Key: "b", Value: "a"},
	); compared >= 0 {
		t.Fatalf("label key comparison = %d", compared)
	}
	if compared := compareDelegationLabels(
		admission.CommandDelegationLabel{Key: "a", Value: "a"},
		admission.CommandDelegationLabel{Key: "a", Value: "b"},
	); compared >= 0 {
		t.Fatalf("label value comparison = %d", compared)
	}
}

func TestComposedCredentialOutputsFailClosed(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	operatorPath := filepath.Join(directory, "operator.token")
	if err := writeOrVerifySiteOperatorToken(operatorPath, "operator-a"); err != nil {
		t.Fatal(err)
	}
	if err := writeOrVerifySiteOperatorToken(operatorPath, "operator-a"); err != nil {
		t.Fatal(err)
	}
	if err := writeOrVerifySiteOperatorToken(operatorPath, "operator-b"); err == nil {
		t.Fatal("operator authority was replaced")
	}
	if err := os.Chmod(operatorPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeOrVerifySiteOperatorToken(operatorPath, "operator-a"); err == nil {
		t.Fatal("insecure retained operator token was accepted")
	}

	trustPath := filepath.Join(directory, "nested", "service-trust.json")
	if err := writeOrVerifyAgentServiceTrust(trustPath, []byte("trust-a\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeOrVerifyAgentServiceTrust(trustPath, []byte("trust-a\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeOrVerifyAgentServiceTrust(trustPath, []byte("trust-b\n")); err == nil {
		t.Fatal("service trust was replaced")
	}
	if err := os.Chmod(trustPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := writeOrVerifyAgentServiceTrust(trustPath, []byte("trust-a\n")); err == nil {
		t.Fatal("service trust with the wrong mode was accepted")
	}

	unsafeParent := filepath.Join(directory, "unsafe")
	if err := os.Mkdir(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := writeOrVerifySiteOperatorToken(filepath.Join(unsafeParent, "token"), "operator"); err == nil {
		t.Fatal("world-writable operator token parent was accepted")
	}
	if err := writeOrVerifyAgentServiceTrust(filepath.Join(unsafeParent, "trust"), []byte("trust\n")); err == nil {
		t.Fatal("world-writable trust parent was accepted")
	}
}

func TestComposedAuthorityValidatorsRejectIdentityDrift(t *testing.T) {
	valid := controlclient.Operator{
		CredentialID: "operator-a", Role: "tenant_operator", TenantID: "tenant-a",
		Token: "token-a", CreatedAt: "2026-07-20T12:00:00Z",
	}
	if err := validateSiteTenantOperator(valid, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	invalidOperators := []controlclient.Operator{
		{},
		{CredentialID: "operator-a", Role: "site_admin", TenantID: "tenant-a", Token: "token-a", CreatedAt: valid.CreatedAt},
		{CredentialID: "operator-a", Role: "tenant_operator", TenantID: "tenant-b", Token: "token-a", CreatedAt: valid.CreatedAt},
		{CredentialID: "operator-a", Role: "tenant_operator", TenantID: "tenant-a", Token: "token a", CreatedAt: valid.CreatedAt},
		{CredentialID: "operator-a", Role: "tenant_operator", TenantID: "tenant-a", Token: " token-a", CreatedAt: valid.CreatedAt},
	}
	for index, operator := range invalidOperators {
		if err := validateSiteTenantOperator(operator, "tenant-a"); err == nil {
			t.Fatalf("invalid operator %d was accepted", index)
		}
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))
	operatorToken := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(operatorToken, []byte("operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := contextCommand([]string{
		"set", "production", "-control-url", "http://127.0.0.1:8443", "-token-file", operatorToken, "-tenant-id", "tenant-a",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := saveSiteOperatorContext("production", "http://127.0.0.1:8443", operatorToken, "", "tenant-a", "node-a"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		label string
		call  func() error
	}{
		{"operator node replacement", func() error {
			return saveSiteOperatorContext("production", "http://127.0.0.1:8443", operatorToken, "", "tenant-a", "node-b")
		}},
		{"task missing operator", func() error {
			return saveSiteTaskContext("missing", "tenant-a", "node-a", "http://127.0.0.1:8091", "token", "trust", "key", "tenant-task-1")
		}},
		{"task node replacement", func() error {
			return saveSiteTaskContext("production", "tenant-a", "node-b", "http://127.0.0.1:8091", "token", "trust", "key", "tenant-task-1")
		}},
	} {
		t.Run(test.label, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("authority replacement was accepted")
			}
		})
	}
}

func TestSiteConnectRejectsAuthorityAndControlDrift(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))
	t.Setenv("STEWARD_CONTEXT", "")
	siteDirectory := filepath.Join(directory, "site")
	if err := siteCommand([]string{"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "admin.token")
	if err := os.WriteFile(tokenPath, []byte("admin-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, arguments := range map[string][]string{
		"missing package":       nil,
		"unknown flag":          {"-unknown"},
		"missing token":         {siteDirectory, "-no-context", "-control-url", "http://127.0.0.1:1"},
		"invalid context":       {siteDirectory, "-no-context", "-control-url", "http://127.0.0.1:1", "-token-file", tokenPath, "-context", "bad context"},
		"invalid node":          {siteDirectory, "-no-context", "-control-url", "http://127.0.0.1:1", "-token-file", tokenPath, "-node-id", "bad node"},
		"invalid request":       {siteDirectory, "-no-context", "-control-url", "http://127.0.0.1:1", "-token-file", tokenPath, "-request-id", "bad request"},
		"output inside package": {siteDirectory, "-no-context", "-control-url", "http://127.0.0.1:1", "-token-file", tokenPath, "-operator-token-out", filepath.Join(siteDirectory, "private", "operator.token")},
		"invalid Control URL":   {siteDirectory, "-no-context", "-control-url", "://bad", "-token-file", tokenPath},
		"invalid site package":  {t.TempDir(), "-no-context", "-control-url", "http://127.0.0.1:1", "-token-file", tokenPath},
		"missing Control CA":    {siteDirectory, "-no-context", "-control-url", "http://127.0.0.1:1", "-token-file", tokenPath, "-ca-file", filepath.Join(directory, "missing-ca")},
		"root token output":     {siteDirectory, "-no-context", "-control-url", "http://127.0.0.1:1", "-token-file", tokenPath, "-operator-token-out", string(filepath.Separator)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := siteConnect(arguments, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid site connection was accepted")
			}
		})
	}

	responses := []struct {
		name     string
		tenant   string
		operator string
	}{
		{"tenant HTTP failure", ``, ``},
		{"tenant mismatch", `{"tenant_id":"tenant-b","state":"active"}`, ``},
		{"tenant inactive", `{"tenant_id":"tenant-a","state":"frozen"}`, ``},
		{"operator HTTP failure", `{"tenant_id":"tenant-a","state":"active"}`, ``},
		{"operator invalid role", `{"tenant_id":"tenant-a","state":"active"}`, `{"credential_id":"operator-a","role":"site_admin","tenant_id":"tenant-a","token":"operator","created_at":"2026-07-20T12:00:00Z"}`},
		{"operator invalid token", `{"tenant_id":"tenant-a","state":"active"}`, `{"credential_id":"operator-a","role":"tenant_operator","tenant_id":"tenant-a","token":"bad token","created_at":"2026-07-20T12:00:00Z"}`},
	}
	for index, response := range responses {
		t.Run(response.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				if request.URL.Path == "/v1/tenants" {
					if response.tenant == "" {
						writer.WriteHeader(http.StatusServiceUnavailable)
						_, _ = writer.Write([]byte(`{"error":"unavailable","message":"tenant unavailable"}`))
						return
					}
					_, _ = writer.Write([]byte(response.tenant))
					return
				}
				if response.operator == "" {
					writer.WriteHeader(http.StatusServiceUnavailable)
					_, _ = writer.Write([]byte(`{"error":"unavailable","message":"operator unavailable"}`))
					return
				}
				_, _ = writer.Write([]byte(response.operator))
			}))
			defer server.Close()
			output := filepath.Join(directory, "operator-"+strconv.Itoa(index)+".token")
			if err := siteConnect([]string{
				siteDirectory, "-no-context", "-control-url", server.URL, "-token-file", tokenPath,
				"-operator-token-out", output, "-context", "context-" + strconv.Itoa(index),
			}, &bytes.Buffer{}); err == nil {
				t.Fatal("Control authority drift was accepted")
			}
		})
	}
}

func TestSiteTaskKeyRejectsUnscopedAuthority(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	siteDirectory := filepath.Join(directory, "site")
	if err := siteCommand([]string{"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	verified, err := verifySitePackage(siteDirectory, "")
	if err != nil {
		t.Fatal(err)
	}
	taskKey, err := readPrivateKey(filepath.Join(siteDirectory, "private", "tenant-task.private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	_, unrelated, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"wrong tenant": func() error {
			return validateSiteTaskKey(verified.policy, "tenant-b", "tenant-task-1", taskKey, []string{"hermes-api"})
		},
		"wrong key ID": func() error {
			return validateSiteTaskKey(verified.policy, "tenant-a", "other", taskKey, []string{"hermes-api"})
		},
		"wrong private key": func() error {
			return validateSiteTaskKey(verified.policy, "tenant-a", "tenant-task-1", unrelated, []string{"hermes-api"})
		},
		"unscoped service": func() error {
			return validateSiteTaskKey(verified.policy, "tenant-a", "tenant-task-1", taskKey, []string{"unknown-api"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("unscoped task authority was accepted")
			}
		})
	}

	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))
	var trust bytes.Buffer
	if err := writeServiceTrustInventory(&trust, gateway.Config{
		ConnectorReceiptNodeID:        "node-a/gateway",
		ConnectorReceiptTenantBudgets: []gateway.ConnectorReceiptTenantBudget{{TenantID: "tenant-a", Bytes: 4 << 20}},
		ServiceOperations: []gateway.ServiceOperation{{
			ServiceID: "hermes-api", ID: "hermes.run", Method: "POST", Path: "/v1/runs",
			ContentType: "application/json", MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20,
			MaxSeconds: 120, MaxPermitSeconds: 300, TaskProtocol: gateway.TaskProtocolLifecycleV1,
			StatusPathPrefix: "/v1/runs/", StatusMaxSeconds: 15, PollIntervalSeconds: 1,
		}},
	}, "node-a", "tenant-a"); err != nil {
		t.Fatal(err)
	}
	trustPath := filepath.Join(directory, "service-trust.json")
	if err := os.WriteFile(trustPath, trust.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	gatewayToken := filepath.Join(directory, "gateway.token")
	if err := os.WriteFile(gatewayToken, []byte("gateway-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelatedKey := filepath.Join(directory, "unrelated.private.pem")
	if err := keygen([]string{
		"-private-out", unrelatedKey, "-public-out", filepath.Join(directory, "unrelated.public"),
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	malformedTrust := filepath.Join(directory, "malformed-trust.json")
	if err := os.WriteFile(malformedTrust, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	badToken := filepath.Join(directory, "bad.token")
	if err := os.WriteFile(badToken, []byte("bad token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, arguments := range map[string][]string{
		"missing trust file":       {siteDirectory, "-trust", filepath.Join(directory, "missing-trust"), "-gateway-token-file", gatewayToken},
		"malformed trust":          {siteDirectory, "-trust", malformedTrust, "-gateway-token-file", gatewayToken},
		"missing Gateway token":    {siteDirectory, "-trust", trustPath, "-gateway-token-file", filepath.Join(directory, "missing-token")},
		"missing task key":         {siteDirectory, "-trust", trustPath, "-gateway-token-file", gatewayToken, "-task-key", filepath.Join(directory, "missing-key")},
		"unrelated task key":       {siteDirectory, "-trust", trustPath, "-gateway-token-file", gatewayToken, "-task-key", unrelatedKey},
		"invalid Gateway token":    {siteDirectory, "-trust", trustPath, "-gateway-token-file", badToken},
		"invalid Gateway URL":      {siteDirectory, "-trust", trustPath, "-gateway-token-file", gatewayToken, "-gateway-url", "://bad"},
		"missing selected context": {siteDirectory, "-trust", trustPath, "-gateway-token-file", gatewayToken},
		"missing named context":    {siteDirectory, "-trust", trustPath, "-gateway-token-file", gatewayToken, "-context", "missing"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := siteTaskConnect(arguments, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid task connection was accepted")
			}
		})
	}
}

func TestSiteTaskAndNodeHelpersRejectMalformedMaterial(t *testing.T) {
	if err := siteTaskCommand(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing site task subcommand was accepted")
	}
	if err := siteTaskCommand([]string{"replace"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown site task subcommand was accepted")
	}
	for _, arguments := range [][]string{
		{"connect"},
		{"connect", "-unknown"},
		{"connect", t.TempDir(), "-trust", "missing", "-gateway-token-file", "missing"},
	} {
		if err := siteTaskCommand(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("site task input %v was accepted", arguments)
		}
	}

	if _, err := decodeSiteNodePublicKey([]byte("not-base64\n")); err == nil {
		t.Fatal("invalid node site root was accepted")
	}
	if _, found := siteInventoryFile(sitePackageInventory{}, "missing"); found {
		t.Fatal("missing site inventory file was reported present")
	}
	if got := siteNodePositionalsLast([]string{"-out", "value"}, 1); !strings.HasPrefix(got[0], "-") {
		t.Fatalf("flag-leading arguments were reordered: %v", got)
	}
	if got := siteNodePositionalsLast(nil, 1); len(got) != 0 {
		t.Fatalf("short arguments changed: %v", got)
	}
	if err := siteNodeCommand(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing site node subcommand was accepted")
	}
	if err := siteNodeCommand([]string{"replace"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown site node subcommand was accepted")
	}
	for _, arguments := range [][]string{
		{"prepare"},
		{"prepare", "-unknown"},
		{"prepare", t.TempDir(), "not a node"},
		{"prepare", t.TempDir(), "node-a", "-valid-for", "0s"},
		{"prepare", filepath.Join(t.TempDir(), "missing"), "node-a"},
		{"activate"},
		{"activate", "-unknown"},
		{"activate", filepath.Join(t.TempDir(), "missing")},
		{"verify"},
		{"verify", "-unknown"},
		{"verify", filepath.Join(t.TempDir(), "missing")},
	} {
		if err := siteNodeCommand(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("site node input %v was accepted", arguments)
		}
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(directory, "activation")
	if err := os.MkdirAll(filepath.Join(created, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	output := siteOutput{path: "private/token", contents: []byte("credential\n"), mode: 0o600}
	if err := writeOrVerifyActivationFile(created, output); err != nil {
		t.Fatal(err)
	}
	if err := writeOrVerifyActivationFile(created, output); err != nil {
		t.Fatal(err)
	}
	output.contents = []byte("replacement\n")
	if err := writeOrVerifyActivationFile(created, output); err == nil {
		t.Fatal("activation authority was replaced")
	}
	if err := os.Chmod(filepath.Join(created, "private", "token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeOrVerifyActivationFile(created, output); err == nil {
		t.Fatal("activation file with the wrong mode was accepted")
	}

	incomplete := filepath.Join(directory, "incomplete")
	if err := os.Mkdir(incomplete, 0o700); err != nil {
		t.Fatal(err)
	}
	if complete, err := readCompletedSiteNodeActivation(incomplete, siteNodeActivationState{}); err != nil || complete != nil {
		t.Fatalf("absent activation marker = %+v, %v", complete, err)
	}
	if err := os.WriteFile(filepath.Join(incomplete, "activation.json"), []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCompletedSiteNodeActivation(incomplete, siteNodeActivationState{}); err == nil {
		t.Fatal("malformed activation marker was accepted")
	}
	if err := os.WriteFile(filepath.Join(incomplete, "activation.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCompletedSiteNodeActivation(incomplete, siteNodeActivationState{}); err == nil {
		t.Fatal("unbound activation marker was accepted")
	}
	if _, err := activationFileInventory(incomplete); err == nil {
		t.Fatal("incomplete activation inventory was accepted")
	}
	if err := writeOrVerifyActivationFile(created, siteOutput{path: "missing/token", contents: []byte("x"), mode: 0o600}); err == nil {
		t.Fatal("activation output with a missing parent was accepted")
	}

	newPath := filepath.Join(directory, "new-package")
	if resolved, err := validatedNewPackagePath(newPath); err != nil || resolved != newPath {
		t.Fatalf("new package path = %q, %v", resolved, err)
	}
	if err := os.Mkdir(newPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedNewPackagePath(newPath); err == nil {
		t.Fatal("existing package output was accepted")
	}
	unsafe := filepath.Join(directory, "world")
	if err := os.Mkdir(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedNewPackagePath(filepath.Join(unsafe, "package")); err == nil {
		t.Fatal("unsafe package parent was accepted")
	}
	if _, err := validatedNewPackagePath(string(filepath.Separator)); err == nil {
		t.Fatal("filesystem root was accepted as a package output")
	}
	if err := verifyFixedPackageLayout(filepath.Join(directory, "missing-layout"), map[string]os.FileMode{}); err == nil {
		t.Fatal("missing package layout was accepted")
	}

	layout := filepath.Join(directory, "layout")
	if err := os.Mkdir(layout, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, "artifact"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected := map[string]os.FileMode{".": 0o700, "artifact": 0o600}
	if err := verifyFixedPackageLayout(layout, expected); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, "extra"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFixedPackageLayout(layout, expected); err == nil {
		t.Fatal("unexpected package path was accepted")
	}
	if err := os.Remove(filepath.Join(layout, "extra")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(layout, "artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyFixedPackageLayout(layout, expected); err == nil {
		t.Fatal("incorrect package mode was accepted")
	}
}
