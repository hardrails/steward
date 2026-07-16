package controlauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

func TestOperatorRequestCredentialIsRecoverableAndDomainIsolated(t *testing.T) {
	manager, err := New(bytes.Repeat([]byte{9}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	firstRaw, first, err := manager.MintOperatorForRequest("operator-request-1", RoleTenantOperator, "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	retryRaw, retry, err := manager.MintOperatorForRequest("operator-request-1", RoleTenantOperator, "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if firstRaw != retryRaw || first.ID != retry.ID || first.RequestID != "operator-request-1" ||
		first.CreatedAt != retry.CreatedAt || !bytes.Equal(first.TokenMAC, retry.TokenMAC) {
		t.Fatalf("exact operator request retry changed bearer or record: first=%+v retry=%+v", first, retry)
	}
	if _, err := manager.AuthenticateOperator(firstRaw, first); err != nil {
		t.Fatalf("authenticate recovered operator: %v", err)
	}
	tampered := first
	tampered.RequestID = "operator-request-2"
	if _, err := manager.AuthenticateOperator(firstRaw, tampered); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("request identity was not MAC-bound: %v", err)
	}
	if _, _, err := manager.MintOperatorForRequest(BootstrapRequestID, RoleSiteAdmin, "", now); err == nil {
		t.Fatal("normal operator issuance accepted the reserved bootstrap request identity")
	}
	bootstrapRaw, bootstrap, err := manager.MintBootstrapOperator(now)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapRetryRaw, bootstrapRetry, err := manager.MintBootstrapOperator(now)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrapRaw != bootstrapRetryRaw || bootstrap.ID != bootstrapRetry.ID ||
		bootstrap.RequestID != BootstrapRequestID || !bytes.Equal(bootstrap.TokenMAC, bootstrapRetry.TokenMAC) {
		t.Fatal("bootstrap operator derivation was not deterministic")
	}
	if bootstrapRaw == firstRaw || bootstrap.ID == first.ID {
		t.Fatal("bootstrap and normal operator derivations share an identity domain")
	}
	otherManager, err := New(bytes.Repeat([]byte{10}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	otherRaw, _, err := otherManager.MintOperatorForRequest("operator-request-1", RoleTenantOperator, "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if otherRaw == firstRaw {
		t.Fatal("operator bearer did not depend on the control auth key")
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

func TestControlInstanceAndEvidenceChallengeBindings(t *testing.T) {
	manager, err := New(bytes.Repeat([]byte{0x4a}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	other, err := New(bytes.Repeat([]byte{0x4b}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	instanceID := manager.InstanceID()
	if instanceID == "" || instanceID == other.InstanceID() || instanceID != manager.InstanceID() {
		t.Fatal("control instance identity is empty, unstable, or not key-bound")
	}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	challenge, err := manager.MintEvidenceChallenge("node-cred-a", "node-a", now, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.VerifyEvidenceChallenge(challenge, "node-cred-a", "node-a", now.Add(time.Minute)); err != nil {
		t.Fatalf("verify exact evidence challenge: %v", err)
	}
	for name, verify := range map[string]func() error{
		"credential": func() error {
			return manager.VerifyEvidenceChallenge(challenge, "node-cred-b", "node-a", now.Add(time.Minute))
		},
		"node": func() error {
			return manager.VerifyEvidenceChallenge(challenge, "node-cred-a", "node-b", now.Add(time.Minute))
		},
		"controller": func() error {
			return other.VerifyEvidenceChallenge(challenge, "node-cred-a", "node-a", now.Add(time.Minute))
		},
		"expired": func() error {
			return manager.VerifyEvidenceChallenge(challenge, "node-cred-a", "node-a", now.Add(5*time.Minute))
		},
		"tampered": func() error {
			replacement := "A"
			if challenge[len(challenge)-1] == 'A' {
				replacement = "B"
			}
			return manager.VerifyEvidenceChallenge(challenge[:len(challenge)-1]+replacement, "node-cred-a", "node-a", now.Add(time.Minute))
		},
	} {
		if err := verify(); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("%s substitution error = %v", name, err)
		}
	}
	if _, err := manager.MintEvidenceChallenge("node-cred-a", "node-a", now, now.Add(11*time.Minute)); err == nil {
		t.Fatal("challenge lifetime above the bound was accepted")
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

func TestEnrollmentIssuanceRequestIsDeterministicAndIssuerBound(t *testing.T) {
	manager, err := New(bytes.Repeat([]byte{0x71}, KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	raw, enrollment, err := manager.MintEnrollmentForRequest(
		"enrollment-request-1", "operator-a", []string{"tenant-b", "tenant-a"}, "node-a", now.Add(time.Hour), now,
	)
	if err != nil || ValidateEnrollment(enrollment) != nil {
		t.Fatalf("deterministic enrollment = (%+v, %v)", enrollment, err)
	}
	retriedRaw, retried, err := manager.MintEnrollmentForRequest(
		"enrollment-request-1", "operator-a", []string{"tenant-a", "tenant-b"}, "node-a", now.Add(time.Hour), now,
	)
	if err != nil || retriedRaw != raw || !reflect.DeepEqual(retried, enrollment) {
		t.Fatalf("exact issuance retry changed output: same_raw=%v same_record=%v error=%v", retriedRaw == raw, reflect.DeepEqual(retried, enrollment), err)
	}
	otherRaw, _, err := manager.MintEnrollmentForRequest(
		"enrollment-request-1", "operator-b", []string{"tenant-a", "tenant-b"}, "node-a", now.Add(time.Hour), now,
	)
	if err != nil || otherRaw == raw {
		t.Fatalf("issuer binding did not change the capability: same=%v error=%v", otherRaw == raw, err)
	}
	tampered := enrollment
	tampered.IssuerCredentialID = "operator-b"
	if _, _, _, err := manager.Exchange(raw, "exchange-1", now.Add(time.Minute), tampered); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered issuer binding error = %v", err)
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
	_, requested, err := manager.MintOperatorForRequest("operator-request-1", RoleTenantOperator, "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	requested.RequestID = "-invalid"
	if ValidateCredential(requested) == nil {
		t.Fatal("malformed operator request identity was accepted")
	}
	_, bootstrap, err := manager.MintBootstrapOperator(now)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap.Role = RoleTenantOperator
	bootstrap.TenantID = "tenant-a"
	if ValidateCredential(bootstrap) == nil {
		t.Fatal("reserved bootstrap identity was accepted outside site-admin scope")
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
	nodeRaw, nodeEnrollment, err := manager.MintEnrollment([]string{"tenant-a"}, "node-a", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	_, nodeCredential, _, err := manager.Exchange(nodeRaw, "request-1", now.Add(time.Minute), nodeEnrollment)
	if err != nil {
		t.Fatal(err)
	}
	nodeCredential.RequestID = "operator-request-1"
	if ValidateCredential(nodeCredential) == nil {
		t.Fatal("node credential accepted an operator request identity")
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
