package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestTenantTaskKeysAreServiceScoped(t *testing.T) {
	publisher, _, _ := ed25519.GenerateKey(rand.Reader)
	publicA, _, _ := ed25519.GenerateKey(rand.Reader)
	publicB, _, _ := ed25519.GenerateKey(rand.Reader)
	policy := testPolicy(publisher)
	policy.Tenants[0].ServiceIDs = []string{"hermes-api", "openclaw-api"}
	policy.Tenants[0].TaskKeys = []TaskKey{
		{KeyID: "hermes-approver", PublicKey: base64.StdEncoding.EncodeToString(publicA), ServiceIDs: []string{"hermes-api"}},
		{KeyID: "shared-approver", PublicKey: base64.StdEncoding.EncodeToString(publicB), ServiceIDs: []string{"hermes-api", "openclaw-api"}},
	}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	keys, err := policy.TrustedTaskKeys("tenant-a", "hermes-api")
	if err != nil || len(keys) != 2 || string(keys["hermes-approver"]) != string(publicA) {
		t.Fatalf("hermes keys=%v err=%v", keys, err)
	}
	keys, err = policy.TrustedTaskKeys("tenant-a", "openclaw-api")
	if err != nil || len(keys) != 1 || string(keys["shared-approver"]) != string(publicB) {
		t.Fatalf("openclaw keys=%v err=%v", keys, err)
	}
	if _, err := policy.TrustedTaskKeys("other-tenant", "hermes-api"); err == nil {
		t.Fatal("cross-tenant task-key lookup succeeded")
	}
}

func TestTenantTaskKeyValidationRejectsAmbiguousAuthority(t *testing.T) {
	publisher, _, _ := ed25519.GenerateKey(rand.Reader)
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	encoded := base64.StdEncoding.EncodeToString(public)
	valid := TaskKey{KeyID: "task-approver", PublicKey: encoded, ServiceIDs: []string{"hermes-api"}}
	tests := []struct {
		name string
		keys []TaskKey
	}{
		{"invalid key ID", []TaskKey{{KeyID: "bad key", PublicKey: encoded, ServiceIDs: valid.ServiceIDs}}},
		{"invalid public key", []TaskKey{{KeyID: valid.KeyID, PublicKey: "not-base64", ServiceIDs: valid.ServiceIDs}}},
		{"noncanonical public key", []TaskKey{{KeyID: valid.KeyID, PublicKey: encoded + "\n", ServiceIDs: valid.ServiceIDs}}},
		{"empty scope", []TaskKey{{KeyID: valid.KeyID, PublicKey: encoded}}},
		{"unknown service", []TaskKey{{KeyID: valid.KeyID, PublicKey: encoded, ServiceIDs: []string{"other-api"}}}},
		{"duplicate service", []TaskKey{{KeyID: valid.KeyID, PublicKey: encoded, ServiceIDs: []string{"hermes-api", "hermes-api"}}}},
		{"unsorted services", []TaskKey{{KeyID: valid.KeyID, PublicKey: encoded, ServiceIDs: []string{"openclaw-api", "hermes-api"}}}},
		{"duplicate key ID", []TaskKey{valid, valid}},
		{"duplicate key material", []TaskKey{valid, {KeyID: "other-approver", PublicKey: encoded, ServiceIDs: valid.ServiceIDs}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(publisher)
			policy.Tenants[0].ServiceIDs = []string{"hermes-api", "openclaw-api"}
			policy.Tenants[0].TaskKeys = test.keys
			if err := policy.Validate(); err == nil {
				t.Fatal("invalid task authority accepted")
			}
		})
	}
	policy := testPolicy(publisher)
	policy.Tenants[0].ServiceIDs = []string{"hermes-api"}
	for index := 0; index < 9; index++ {
		key, _, _ := ed25519.GenerateKey(rand.Reader)
		policy.Tenants[0].TaskKeys = append(policy.Tenants[0].TaskKeys, TaskKey{
			KeyID: "task-" + strings.Repeat("x", index+1), PublicKey: base64.StdEncoding.EncodeToString(key),
			ServiceIDs: []string{"hermes-api"},
		})
	}
	if err := policy.Validate(); err == nil {
		t.Fatal("too many task authorities accepted")
	}
}

func TestTenantTaskKeyValidationRejectsCrossTenantKeyMaterial(t *testing.T) {
	publisher, _, _ := ed25519.GenerateKey(rand.Reader)
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	encoded := base64.StdEncoding.EncodeToString(public)
	policy := testPolicy(publisher)
	policy.Tenants[0].ServiceIDs = []string{"hermes-api"}
	policy.Tenants[0].TaskKeys = []TaskKey{{
		KeyID: "tenant-a-approver", PublicKey: encoded, ServiceIDs: []string{"hermes-api"},
	}}
	tenantB := policy.Tenants[0]
	tenantB.TenantID = "tenant-b"
	tenantB.TaskKeys = []TaskKey{{
		KeyID: "tenant-b-approver", PublicKey: encoded, ServiceIDs: []string{"hermes-api"},
	}}
	policy.Tenants = append(policy.Tenants, tenantB)
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "multiple tenants") {
		t.Fatalf("cross-tenant task authority error=%v", err)
	}
}
