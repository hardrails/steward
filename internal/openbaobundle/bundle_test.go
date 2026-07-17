package openbaobundle

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/secretmaterial"
)

func TestCompileProducesClosedSecretFreeHardenedBundle(t *testing.T) {
	plan := validPlan()
	plan.Bindings = append(plan.Bindings, Binding{TenantID: "tenant-a", SecretID: "inference", Purpose: secretmaterial.PurposeInference,
		KVPath: "steward-kv/data/tenant-a/inference", Field: "token", ExpectedVersion: 7})
	files, err := Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("files=%d", len(files))
	}
	byName := make(map[string]File)
	for _, file := range files {
		byName[file.Name] = file
	}
	for _, name := range []string{"agent.hcl", "materialization.json", "openbao-read-policy.hcl", "steward-openbao-agent.service"} {
		if byName[name].Name == "" || byName[name].Mode != 0o640 {
			t.Fatalf("missing or unsafe %s: %#v", name, byName[name])
		}
	}
	agent := string(byName["agent.hcl"].Data)
	for _, required := range []string{"https://bao.internal:8200", "remove_secret_id_file_after_reading = true", "create_dest_dirs = false", "error_on_missing_key = true", "perms = \"0600\"", "backup = false", ".Data.metadata.version"} {
		if !strings.Contains(agent, required) {
			t.Fatalf("agent config omits %q:\n%s", required, agent)
		}
	}
	for _, forbidden := range []string{"listener", "sink", "cache {", "api_proxy", "super-secret"} {
		if strings.Contains(agent, forbidden) {
			t.Fatalf("agent config contains %q", forbidden)
		}
	}
	policy := string(byName["openbao-read-policy.hcl"].Data)
	if strings.Count(policy, `capabilities = ["read"]`) != 2 || strings.Contains(policy, "list") || strings.Contains(policy, "update") || strings.Contains(policy, "*") {
		t.Fatalf("policy is not exact read-only:\n%s", policy)
	}
	unit := string(byName["steward-openbao-agent.service"].Data)
	for _, required := range []string{"NoNewPrivileges=true", "ProtectSystem=strict", "CapabilityBoundingSet=", "MemoryDenyWriteExecute=true", "secret materialization prepare"} {
		if !strings.Contains(unit, required) {
			t.Fatalf("unit omits %q", required)
		}
	}
	secretIDDirectory := "/run/steward-openbao"
	if strings.Contains(lineWithPrefix(unit, "ReadOnlyPaths="), secretIDDirectory) || !strings.Contains(lineWithPrefix(unit, "ReadWritePaths="), secretIDDirectory) {
		t.Fatalf("SecretID directory must be writable only so auto-auth can remove it:\n%s", unit)
	}
	var manifest secretmaterial.Manifest
	if err := json.Unmarshal(byName["materialization.json"].Data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != secretmaterial.ManifestSchemaV2 || len(manifest.Bindings) != 2 || manifest.Bindings[0].SecretID != "inference" || manifest.Bindings[0].ExpectedEpoch != 7 {
		t.Fatalf("manifest=%#v", manifest)
	}
}

func lineWithPrefix(value, prefix string) string {
	for _, line := range strings.Split(value, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func TestCompileRejectsBroadOrAliasedAuthority(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"http", func(p *Plan) { p.OpenBaoAddress = "http://bao.internal:8200" }},
		{"address path", func(p *Plan) { p.OpenBaoAddress = "https://bao.internal:8200/v1" }},
		{"wildcard", func(p *Plan) { p.Bindings[0].KVPath = "steward-kv/data/tenant-a/*" }},
		{"traversal", func(p *Plan) { p.Bindings[0].KVPath = "steward-kv/data/../tenant-a/key" }},
		{"not kv2", func(p *Plan) { p.Bindings[0].KVPath = "steward-kv/tenant-a/key" }},
		{"zero version", func(p *Plan) { p.Bindings[0].ExpectedVersion = 0 }},
		{"path alias", func(p *Plan) { p.StatusRoot = p.SecretRoot }},
		{"shared source", func(p *Plan) {
			p.Bindings = append(p.Bindings, Binding{TenantID: "tenant-b", SecretID: "key", Purpose: secretmaterial.PurposeConnector, KVPath: p.Bindings[0].KVPath, Field: p.Bindings[0].Field, ExpectedVersion: 1})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := validPlan()
			test.mutate(&plan)
			if _, err := Compile(plan); err == nil {
				t.Fatal("accepted unsafe plan")
			}
		})
	}
}

func validPlan() Plan {
	return Plan{SchemaVersion: PlanSchemaV1, OpenBaoAddress: "https://bao.internal:8200", AuthMount: "auth/approle",
		CAFile: "/etc/steward/openbao/ca.pem", RoleIDFile: "/etc/steward/openbao/role-id", SecretIDFile: "/run/steward-openbao/secret-id",
		BaoPath: "/usr/bin/bao", StewardctlPath: "/usr/bin/stewardctl", InstallRoot: "/etc/steward/openbao-agent",
		SecretRoot: "/var/lib/steward-gateway/secrets", StatusRoot: "/var/lib/steward-gateway/secret-status",
		Bindings: []Binding{{TenantID: "tenant-b", SecretID: "tickets", Purpose: secretmaterial.PurposeConnector, KVPath: "steward-kv/data/tenant-b/tickets", Field: "value", ExpectedVersion: 3}}}
}
