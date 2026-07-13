package controlauth

import (
	"bytes"
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
}

func TestEnrollmentExchangeIsDeterministicAndOneRequestOnly(t *testing.T) {
	manager, err := New(bytes.Repeat([]byte{11}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	raw, enrollment, err := manager.MintEnrollment("tenant-a", "node-a", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
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
	if err != nil || identity.TenantID != "tenant-a" || identity.NodeID != "node-a" || identity.Audience != "executor" {
		t.Fatalf("node authentication = (%+v, %v)", identity, err)
	}
	if _, _, _, err := manager.Exchange(raw, "request-2", now.Add(2*time.Minute), used); !errors.Is(err, ErrEnrollmentConsumed) {
		t.Fatalf("second request error = %v", err)
	}
	if _, _, _, err := manager.Exchange(raw, "request-1", now.Add(2*time.Hour), used); !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("expired retry error = %v", err)
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
	_, enrollment, err := manager.MintEnrollment("tenant-a", "node-a", now.Add(time.Hour), now)
	if err != nil || ValidateEnrollment(enrollment) != nil {
		t.Fatalf("enrollment validation = (%v, %v)", err, ValidateEnrollment(enrollment))
	}
	enrollment.CredentialID = "orphan"
	if ValidateEnrollment(enrollment) == nil {
		t.Fatal("partial consumption was accepted")
	}
}
