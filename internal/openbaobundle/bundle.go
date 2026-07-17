// Package openbaobundle compiles a bounded, non-secret deployment plan into a
// deterministic OpenBao Agent handoff for Steward Gateway. It never accepts or
// emits secret values, OpenBao tokens, RoleIDs, or SecretIDs.
package openbaobundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/secretmaterial"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	PlanSchemaV1 = "steward.openbao-materializer-plan.v1"
	maxBindings  = 512
	maxPlanBytes = 1 << 20
)

type Plan struct {
	SchemaVersion  string    `json:"schema_version"`
	OpenBaoAddress string    `json:"openbao_address"`
	AuthMount      string    `json:"auth_mount"`
	CAFile         string    `json:"ca_file"`
	RoleIDFile     string    `json:"role_id_file"`
	SecretIDFile   string    `json:"secret_id_file"`
	BaoPath        string    `json:"bao_path"`
	StewardctlPath string    `json:"stewardctl_path"`
	InstallRoot    string    `json:"install_root"`
	SecretRoot     string    `json:"secret_root"`
	StatusRoot     string    `json:"status_root"`
	Bindings       []Binding `json:"bindings"`
}

type Binding struct {
	TenantID        string                 `json:"tenant_id"`
	SecretID        string                 `json:"secret_id"`
	Purpose         secretmaterial.Purpose `json:"purpose"`
	KVPath          string                 `json:"kv_path"`
	Field           string                 `json:"field"`
	ExpectedVersion uint64                 `json:"expected_version"`
}

type File struct {
	Name string
	Mode uint32
	Data []byte
}

func LoadPlan(path string) (Plan, error) {
	raw, err := securefile.Read(path, maxPlanBytes, securefile.TrustFile)
	if err != nil {
		return Plan{}, fmt.Errorf("read OpenBao materializer plan: %w", err)
	}
	var plan Plan
	if err := dsse.DecodeStrictInto(raw, maxPlanBytes, &plan); err != nil {
		return Plan{}, fmt.Errorf("decode OpenBao materializer plan: %w", err)
	}
	if _, err := validate(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

var (
	identifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	fieldPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	providerPathPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]{0,511}$`)
)

func Compile(plan Plan) ([]File, error) {
	bindings, err := validate(plan)
	if err != nil {
		return nil, err
	}
	manifest := secretmaterial.Manifest{SchemaVersion: secretmaterial.ManifestSchemaV2}
	for _, binding := range bindings {
		manifest.Bindings = append(manifest.Bindings, secretmaterial.Binding{
			TenantID: binding.TenantID, SecretID: binding.SecretID, Purpose: binding.Purpose,
			ExpectedEpoch: binding.ExpectedVersion,
		})
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode materialization manifest: %w", err)
	}
	manifestRaw = append(manifestRaw, '\n')
	return []File{
		{Name: "agent.hcl", Mode: 0o640, Data: []byte(agentConfig(plan, bindings))},
		{Name: "materialization.json", Mode: 0o640, Data: manifestRaw},
		{Name: "openbao-read-policy.hcl", Mode: 0o640, Data: []byte(readPolicy(bindings))},
		{Name: "steward-openbao-agent.service", Mode: 0o640, Data: []byte(systemdUnit(plan))},
	}, nil
}

func validate(plan Plan) ([]Binding, error) {
	if plan.SchemaVersion != PlanSchemaV1 || len(plan.Bindings) == 0 || len(plan.Bindings) > maxBindings {
		return nil, fmt.Errorf("OpenBao materializer plan requires schema %q and 1 through %d bindings", PlanSchemaV1, maxBindings)
	}
	address, err := url.Parse(plan.OpenBaoAddress)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil ||
		address.RawQuery != "" || address.Fragment != "" || (address.Path != "" && address.Path != "/") {
		return nil, errors.New("OpenBao address must be an HTTPS origin without credentials, path, query, or fragment")
	}
	if !providerPath(plan.AuthMount) || strings.Contains(plan.AuthMount, "/data/") {
		return nil, errors.New("OpenBao auth mount must be a bounded relative provider path")
	}
	for name, value := range map[string]string{
		"CA file": plan.CAFile, "RoleID file": plan.RoleIDFile, "SecretID file": plan.SecretIDFile,
		"bao path": plan.BaoPath, "stewardctl path": plan.StewardctlPath, "install root": plan.InstallRoot,
		"secret root": plan.SecretRoot, "status root": plan.StatusRoot,
	} {
		if !cleanAbsolute(value) {
			return nil, fmt.Errorf("%s must be a clean absolute path", name)
		}
	}
	paths := []string{plan.CAFile, plan.RoleIDFile, plan.SecretIDFile, plan.BaoPath, plan.StewardctlPath,
		plan.InstallRoot, plan.SecretRoot, plan.StatusRoot}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if paths[i] == paths[j] {
				return nil, errors.New("OpenBao materializer paths must be distinct")
			}
		}
	}
	bindings := append([]Binding(nil), plan.Bindings...)
	slices.SortFunc(bindings, func(left, right Binding) int {
		if value := strings.Compare(left.TenantID, right.TenantID); value != 0 {
			return value
		}
		return strings.Compare(left.SecretID, right.SecretID)
	})
	identities := make(map[string]struct{}, len(bindings))
	sources := make(map[string]struct{}, len(bindings))
	for index, binding := range bindings {
		if !identifierPattern.MatchString(binding.TenantID) || !identifierPattern.MatchString(binding.SecretID) ||
			(binding.Purpose != secretmaterial.PurposeInference && binding.Purpose != secretmaterial.PurposeConnector) ||
			!providerPath(binding.KVPath) || !strings.Contains(binding.KVPath, "/data/") ||
			!fieldPattern.MatchString(binding.Field) || binding.ExpectedVersion == 0 {
			return nil, fmt.Errorf("OpenBao materializer binding %d is invalid", index)
		}
		identity := binding.TenantID + "\x00" + binding.SecretID
		if _, exists := identities[identity]; exists {
			return nil, fmt.Errorf("duplicate materialization target %q/%q", binding.TenantID, binding.SecretID)
		}
		identities[identity] = struct{}{}
		// A provider field has one tenant-scoped destination. Reuse would couple
		// independent tenant lifecycles and make revocation ambiguous.
		source := binding.KVPath + "\x00" + binding.Field
		if _, exists := sources[source]; exists {
			return nil, errors.New("one OpenBao field cannot be shared across materialization targets")
		}
		sources[source] = struct{}{}
	}
	return bindings, nil
}

func cleanAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func providerPath(value string) bool {
	return providerPathPattern.MatchString(value) && filepath.IsLocal(value) && filepath.ToSlash(filepath.Clean(value)) == value &&
		!strings.Contains(value, "//")
}

func hclString(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func agentConfig(plan Plan, bindings []Binding) string {
	var out strings.Builder
	fmt.Fprintf(&out, "vault {\n  address = %s\n  ca_cert = %s\n  retry {\n    num_retries = 5\n  }\n}\n\n", hclString(plan.OpenBaoAddress), hclString(plan.CAFile))
	fmt.Fprintf(&out, "auto_auth {\n  method \"approle\" {\n    mount_path = %s\n    config = {\n      role_id_file_path = %s\n      secret_id_file_path = %s\n      remove_secret_id_file_after_reading = true\n    }\n  }\n}\n\n", hclString(plan.AuthMount), hclString(plan.RoleIDFile), hclString(plan.SecretIDFile))
	out.WriteString("template_config {\n  exit_on_retry_failure = true\n  static_secret_render_interval = \"5m\"\n}\n")
	for _, binding := range bindings {
		secretDestination := filepath.Join(plan.SecretRoot, binding.TenantID, binding.SecretID)
		epochDestination := filepath.Join(plan.StatusRoot, binding.TenantID, binding.SecretID+".epoch")
		secretTemplate := fmt.Sprintf(`{{- with secret %q -}}{{- index .Data.data %q -}}{{- end -}}`, binding.KVPath, binding.Field)
		epochTemplate := fmt.Sprintf(`{{- with secret %q -}}{{- .Data.metadata.version -}}{{- end -}}`, binding.KVPath)
		for _, template := range []struct{ contents, destination string }{{secretTemplate, secretDestination}, {epochTemplate, epochDestination}} {
			fmt.Fprintf(&out, "\ntemplate {\n  contents = %s\n  destination = %s\n  create_dest_dirs = false\n  error_on_missing_key = true\n  perms = \"0600\"\n  backup = false\n}\n", hclString(template.contents), hclString(template.destination))
		}
	}
	return out.String()
}

func readPolicy(bindings []Binding) string {
	var out strings.Builder
	for index, binding := range bindings {
		if index > 0 {
			out.WriteByte('\n')
		}
		fmt.Fprintf(&out, "path %s {\n  capabilities = [\"read\"]\n}\n", hclString(binding.KVPath))
	}
	return out.String()
}

func systemdUnit(plan Plan) string {
	manifestPath := filepath.Join(plan.InstallRoot, "materialization.json")
	configPath := filepath.Join(plan.InstallRoot, "agent.hcl")
	return fmt.Sprintf(`[Unit]
Description=Steward OpenBao secret materializer
After=network-online.target
Wants=network-online.target
Before=steward-gateway.service

[Service]
Type=simple
User=steward-gateway
Group=steward-gateway
UMask=0077
ExecStartPre=%s secret materialization prepare -manifest %s -root %s -status-root %s
ExecStart=%s agent -config=%s -log-format=json -log-level=info
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadOnlyPaths=%s %s %s
ReadWritePaths=%s %s %s

[Install]
WantedBy=multi-user.target
`, plan.StewardctlPath, manifestPath, plan.SecretRoot, plan.StatusRoot, plan.BaoPath, configPath,
		plan.InstallRoot, plan.CAFile, plan.RoleIDFile,
		plan.SecretRoot, plan.StatusRoot, filepath.Dir(plan.SecretIDFile))
}
