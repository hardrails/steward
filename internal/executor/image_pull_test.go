package executor

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestEncodeRegistryAuthProducesDockerScopedHeader(t *testing.T) {
	raw := []byte(`{"schema_version":"steward.registry-auth.v1","registry":"registry.site.test:5443","username":"robot","password":"secret"}`)
	header, err := EncodeRegistryAuth(raw, "registry.site.test:5443")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.URLEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]string
	if err := json.Unmarshal(decoded, &value); err != nil {
		t.Fatal(err)
	}
	if value["serveraddress"] != "registry.site.test:5443" || value["username"] != "robot" ||
		value["password"] != "secret" || value["schema_version"] != "" || value["registry"] != "" {
		t.Fatalf("Docker registry header = %#v", value)
	}
}

func TestEncodeRegistryAuthSupportsEachExclusiveTokenMode(t *testing.T) {
	for field := range map[string]string{"identity_token": "identity", "registry_token": "registry"} {
		raw := []byte(`{"schema_version":"steward.registry-auth.v1","registry":"registry.site.test","` + field + `":"token"}`)
		if _, err := EncodeRegistryAuth(raw, "registry.site.test"); err != nil {
			t.Fatalf("%s mode: %v", field, err)
		}
	}
	if _, err := EncodeRegistryAuth(nil, "registry.site.test"); err == nil {
		t.Fatal("empty registry authentication was accepted")
	}
	if _, err := EncodeRegistryAuth([]byte(`{}`), "HTTPS://registry.site.test"); err == nil {
		t.Fatal("invalid expected registry authority was accepted")
	}
}

func TestEncodeRegistryAuthRejectsAmbiguousOrWrongScope(t *testing.T) {
	for _, raw := range []string{
		`{}`,
		`{"schema_version":"steward.registry-auth.v1","registry":"other.test","identity_token":"token"}`,
		`{"schema_version":"steward.registry-auth.v1","registry":"registry.site.test","username":"robot"}`,
		`{"schema_version":"steward.registry-auth.v1","registry":"registry.site.test","username":"robot","password":"secret","identity_token":"token"}`,
		`{"schema_version":"steward.registry-auth.v1","registry":"registry.site.test","identity_token":"token","unknown":true}`,
		`{"schema_version":"steward.registry-auth.v1","registry":"registry.site.test","identity_token":"token"}{}`,
	} {
		if _, err := EncodeRegistryAuth([]byte(raw), "registry.site.test"); err == nil {
			t.Fatalf("invalid registry auth was accepted: %s", raw)
		}
	}
}

func TestRegistryAuthorityAndImageReferenceMatchExactly(t *testing.T) {
	for _, valid := range []string{"registry.site.test", "registry.site.test:5443", "localhost:5000", "[2001:db8::1]:5443"} {
		if !ValidRegistryAuthority(valid) {
			t.Fatalf("valid registry authority rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", "HTTPS://registry.test", "https://registry.test", "registry.test/path", "user@registry.test", "REGISTRY.test", " registry.test"} {
		if ValidRegistryAuthority(invalid) {
			t.Fatalf("invalid registry authority accepted: %q", invalid)
		}
	}
	reference := "registry.site.test/agents/hermes@sha256:" + strings.Repeat("a", 64)
	if !imageReferenceUsesRegistry(reference, "registry.site.test") ||
		imageReferenceUsesRegistry(reference, "site.test") ||
		imageReferenceUsesRegistry("registry.site.test/agents/hermes:latest", "registry.site.test") {
		t.Fatal("registry match did not require an exact authority and immutable digest")
	}
}
