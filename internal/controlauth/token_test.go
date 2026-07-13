package controlauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOperatorAuthenticationAndTenantScope(t *testing.T) {
	manager, err := New(bytes.Repeat([]byte{7}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	adminToken, admin, err := manager.MintOperator(RoleSiteAdmin, "", now)
	if err != nil {
		t.Fatal(err)
	}
	adminIdentity, err := manager.AuthenticateOperator(adminToken, admin)
	if err != nil || !AuthorizedTenant(adminIdentity, "tenant-a") || !IsSiteAdmin(adminIdentity) {
		t.Fatalf("admin authentication = (%+v, %v)", adminIdentity, err)
	}
	operatorToken, operator, err := manager.MintOperator(RoleTenantOperator, "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	operatorIdentity, err := manager.AuthenticateOperator(operatorToken, operator)
	if err != nil || !AuthorizedTenant(operatorIdentity, "tenant-a") || AuthorizedTenant(operatorIdentity, "tenant-b") {
		t.Fatalf("tenant authentication = (%+v, %v)", operatorIdentity, err)
	}
	changed := operator
	changed.TokenMAC = append([]byte(nil), operator.TokenMAC...)
	changed.TokenMAC[0] ^= 0xff
	if _, err := manager.AuthenticateOperator(operatorToken, changed); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("changed MAC error = %v", err)
	}
	if _, err := manager.AuthenticateOperator(operatorToken+"x", operator); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("changed token error = %v", err)
	}
	changed = operator
	changed.TenantID = "tenant-b"
	if _, err := manager.AuthenticateOperator(operatorToken, changed); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("changed operator scope error = %v", err)
	}
}

func TestEnrollmentExchangeIsDeterministicAndOneRequestOnly(t *testing.T) {
	manager, err := New(bytes.Repeat([]byte{11}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	inputTenants := []string{"tenant-b", "tenant-a"}
	raw, enrollment, err := manager.MintEnrollment(inputTenants, "node-a", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	inputTenants[0] = "tampered"
	if !equalStrings(enrollment.TenantIDs, []string{"tenant-a", "tenant-b"}) {
		t.Fatalf("enrollment tenant bindings = %v", enrollment.TenantIDs)
	}
	firstFile, firstCredential, used, err := manager.Exchange(raw, "request-1", now.Add(time.Minute), enrollment)
	if err != nil {
		t.Fatal(err)
	}
	secondFile, secondCredential, secondUsed, err := manager.Exchange(raw, "request-1", now.Add(2*time.Minute), used)
	if err != nil {
		t.Fatal(err)
	}
	if firstFile != secondFile || firstCredential.ID != secondCredential.ID ||
		!bytes.Equal(firstCredential.TokenMAC, secondCredential.TokenMAC) || secondUsed.RequestID != "request-1" {
		t.Fatalf("exact retry changed credential: first=%+v second=%+v", firstFile, secondFile)
	}
	identity, err := manager.AuthenticateNode(firstFile.Credential, secondCredential)
	if err != nil || identity.NodeID != "node-a" || identity.Audience != "executor" ||
		!NodeAuthorizedTenant(identity, "tenant-a") || !NodeAuthorizedTenant(identity, "tenant-b") || NodeAuthorizedTenant(identity, "tenant-c") {
		t.Fatalf("node authentication = (%+v, %v)", identity, err)
	}
	identity.TenantIDs[0] = "mutated"
	if firstCredential.TenantIDs[0] != "tenant-a" {
		t.Fatal("authenticated identity aliases durable tenant bindings")
	}
	wire, err := json.Marshal(firstFile)
	if err != nil || bytes.Contains(wire, []byte("tenant")) {
		t.Fatalf("Executor v2 credential wire shape leaked bindings: %s (%v)", wire, err)
	}
	if _, _, _, err := manager.Exchange(raw, "request-2", now.Add(2*time.Minute), used); !errors.Is(err, ErrEnrollmentConsumed) {
		t.Fatalf("second request error = %v", err)
	}
	if _, _, _, err := manager.Exchange(raw, "request-1", now.Add(2*time.Hour), used); !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("expired retry error = %v", err)
	}
}

func TestEnrollmentRejectsDuplicateBindingsAndTampering(t *testing.T) {
	manager, err := New(bytes.Repeat([]byte{17}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	if _, _, err := manager.MintEnrollment([]string{"tenant-a", "tenant-a"}, "node-a", now.Add(time.Hour), now); err == nil {
		t.Fatal("duplicate tenant binding was accepted")
	}
	raw, enrollment, err := manager.MintEnrollment([]string{"tenant-a", "tenant-b"}, "node-a", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	tamperedEnrollment := enrollment
	tamperedEnrollment.TenantIDs = []string{"tenant-a", "tenant-c"}
	if _, _, _, err := manager.Exchange(raw, "request-1", now.Add(time.Minute), tamperedEnrollment); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered enrollment error = %v", err)
	}
	file, credential, _, err := manager.Exchange(raw, "request-1", now.Add(time.Minute), enrollment)
	if err != nil {
		t.Fatal(err)
	}
	tamperedCredential := credential
	tamperedCredential.TenantIDs = []string{"tenant-a", "tenant-c"}
	if _, err := manager.AuthenticateNode(file.Credential, tamperedCredential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered node binding error = %v", err)
	}
	unsortedCredential := credential
	unsortedCredential.TenantIDs = []string{"tenant-b", "tenant-a"}
	if _, err := manager.AuthenticateNode(file.Credential, unsortedCredential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unordered durable binding error = %v", err)
	}
}

func TestAuthKeyIsExclusiveAndOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.key")
	if _, err := InitializeKey(path); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeKey(path); err == nil {
		t.Fatal("InitializeKey overwrote an existing key")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Size() != KeyBytes {
		t.Fatalf("key info = (%v, %v)", info, err)
	}
	if _, err := LoadKey(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("LoadKey accepted group-readable key")
	}
	link := filepath.Join(dir, "auth-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(link); err == nil {
		t.Fatal("LoadKey accepted symlink")
	}
}

func TestDurableRecordValidation(t *testing.T) {
	manager, _ := New(bytes.Repeat([]byte{3}, KeyBytes))
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	_, credential, err := manager.MintOperator(RoleTenantOperator, "tenant-a", now)
	if err != nil || ValidateCredential(credential) != nil {
		t.Fatalf("credential validation = (%v, %v)", err, ValidateCredential(credential))
	}
	credential.TenantID = ""
	if ValidateCredential(credential) == nil {
		t.Fatal("invalid role scope was accepted")
	}
	credential.TenantID = "tenant-a"
	credential.Revoked = true
	if ValidateCredential(credential) == nil {
		t.Fatal("revocation without a timestamp was accepted")
	}
	credential.RevokedAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	if ValidateCredential(credential) != nil {
		t.Fatal("complete credential revocation was rejected")
	}
	_, enrollment, err := manager.MintEnrollment([]string{"tenant-a"}, "node-a", now.Add(time.Hour), now)
	if err != nil || ValidateEnrollment(enrollment) != nil {
		t.Fatalf("enrollment validation = (%v, %v)", err, ValidateEnrollment(enrollment))
	}
	enrollment.CredentialID = "orphan"
	if ValidateEnrollment(enrollment) == nil {
		t.Fatal("partial consumption was accepted")
	}
	enrollment.CredentialID = ""
	enrollment.Revoked = true
	if ValidateEnrollment(enrollment) == nil {
		t.Fatal("enrollment revocation without a timestamp was accepted")
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
