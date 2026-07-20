package controlstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

type recordsFixture struct {
	store       *Store
	auth        *controlauth.Manager
	admin       controlauth.Identity
	adminRaw    string
	adminRecord controlauth.Credential
	now         time.Time
	dir         string
	limits      Limits
}

func newRecordsFixture(t *testing.T, limits Limits) recordsFixture {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "control")
	store, err := Initialize(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := controlauth.New(bytes.Repeat([]byte{31}, controlauth.KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	raw, credential, created, err := store.BootstrapSiteAdmin(auth, now)
	if err != nil || !created {
		t.Fatalf("bootstrap site administrator = (%v, %v)", created, err)
	}
	admin, err := store.AuthenticateOperator(auth, raw)
	if err != nil {
		t.Fatal(err)
	}
	return recordsFixture{
		store: store, auth: auth, admin: admin, adminRaw: raw, adminRecord: credential,
		now: now, dir: directory, limits: limits,
	}
}

func (fixture recordsFixture) createTenant(t *testing.T, tenantID string) {
	t.Helper()
	if _, created, err := fixture.store.CreateTenant(fixture.admin, tenantID, fixture.now); err != nil || !created {
		t.Fatalf("create tenant %s = (%v, %v)", tenantID, created, err)
	}
}

func (fixture recordsFixture) createNode(t *testing.T, tenants ...string) (string, controlauth.NodeIdentity) {
	t.Helper()
	raw, enrollment, _, err := fixture.store.CreateEnrollment(fixture.admin, fixture.auth, "node-1", tenants, fixture.now.Add(time.Hour), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	private := newEvidencePrivateKey(t)
	proof := evidenceIdentityProof(t, fixture.auth, enrollment, private)
	credential, err := fixture.store.ExchangeEnrollment(fixture.auth, raw, "request-1", proof, fixture.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := fixture.store.AuthenticateNode(fixture.auth, credential.Credential)
	if err != nil {
		t.Fatal(err)
	}
	return credential.Credential, identity
}

func newEvidencePrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func evidenceIdentityProof(t *testing.T, auth *controlauth.Manager, enrollment controlauth.Enrollment, private ed25519.PrivateKey) controlprotocol.ExecutorEvidenceIdentityProofV1 {
	t.Helper()
	return signedEvidenceIdentityProof(
		t, auth.InstanceID(), enrollment.ID, enrollment.NodeID, enrollment.NodeID, 1, private,
	)
}

func signedEvidenceIdentityProof(t *testing.T, controllerID, enrollmentID, controlNodeID, receiptNodeID string, epoch uint64, private ed25519.PrivateKey) controlprotocol.ExecutorEvidenceIdentityProofV1 {
	t.Helper()
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		controllerID, enrollmentID, controlNodeID, receiptNodeID, epoch, private.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, private)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestBootstrapSiteAdminRetrySurvivesReopenOnlyWhilePristine(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	assertBearerNotPersisted(t, fixture.dir, fixture.adminRaw)
	retryRaw, retryRecord, created, err := fixture.store.BootstrapSiteAdmin(fixture.auth, fixture.now.Add(time.Minute))
	if err != nil || created || retryRaw != fixture.adminRaw || !credentialsEqual(retryRecord, fixture.adminRecord) {
		t.Fatalf("bootstrap retry = (same_raw=%v, same_record=%v, created=%v, err=%v)",
			retryRaw == fixture.adminRaw, credentialsEqual(retryRecord, fixture.adminRecord), created, err)
	}
	status, err := fixture.store.Status()
	if err != nil || status.Credentials != 1 {
		t.Fatalf("status = (%+v, %v)", status, err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatalf("reopen after credential WAL mutation: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	fixture.store = reopened
	if status, err := reopened.Status(); err != nil || status.Credentials != 1 || status.Sequence != 1 {
		t.Fatalf("reopened status = (%+v, %v)", status, err)
	}
	retryRaw, retryRecord, created, err = reopened.BootstrapSiteAdmin(fixture.auth, fixture.now.Add(2*time.Minute))
	if err != nil || created || retryRaw != fixture.adminRaw || !credentialsEqual(retryRecord, fixture.adminRecord) {
		t.Fatalf("reopened bootstrap retry = (same_raw=%v, same_record=%v, created=%v, err=%v)",
			retryRaw == fixture.adminRaw, credentialsEqual(retryRecord, fixture.adminRecord), created, err)
	}
	fixture.createTenant(t, "tenant-a")
	if _, _, _, err := reopened.BootstrapSiteAdmin(fixture.auth, fixture.now.Add(3*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("bootstrap with retained tenant error = %v", err)
	}
}

func TestBootstrapSiteAdminDoesNotReproduceRevokedCredential(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	backupRaw, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "backup-site-admin", controlauth.RoleSiteAdmin, "", fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := fixture.store.AuthenticateOperator(fixture.auth, backupRaw)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := fixture.store.RevokeCredential(backup, fixture.adminRecord.ID, fixture.now.Add(2*time.Minute)); err != nil || !revoked {
		t.Fatalf("revoke bootstrap credential = (%v, %v)", revoked, err)
	}
	if _, _, _, err := fixture.store.BootstrapSiteAdmin(fixture.auth, fixture.now.Add(3*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked bootstrap retry error = %v", err)
	}
}

func TestOperatorRevocationRetainsOneRecoverableSiteAdministrator(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	if revoked, err := fixture.store.RevokeOperator(
		fixture.admin, fixture.adminRecord.ID, fixture.now.Add(time.Minute),
	); !errors.Is(err, ErrConflict) || revoked {
		t.Fatalf("last site administrator revocation = (%v, %v)", revoked, err)
	}
	if _, err := fixture.store.AuthenticateOperator(fixture.auth, fixture.adminRaw); err != nil {
		t.Fatalf("rejected revocation invalidated the bootstrap administrator: %v", err)
	}

	backupRaw, backupRecord, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "backup-site-admin", controlauth.RoleSiteAdmin, "", fixture.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := fixture.store.AuthenticateOperator(fixture.auth, backupRaw)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := fixture.store.RevokeOperator(
		backup, fixture.adminRecord.ID, fixture.now.Add(3*time.Minute),
	); err != nil || !revoked {
		t.Fatalf("revocation with a backup administrator = (%v, %v)", revoked, err)
	}
	if revoked, err := fixture.store.RevokeOperator(
		backup, backupRecord.ID, fixture.now.Add(4*time.Minute),
	); !errors.Is(err, ErrConflict) || revoked {
		t.Fatalf("backup administrator revoked itself as the last administrator = (%v, %v)", revoked, err)
	}
}

func TestDetachedOperatorAndNodeIdentitiesAreFencedAtMutationTime(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	backupRaw, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "atomic-revocation-backup", controlauth.RoleSiteAdmin, "", fixture.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := fixture.store.AuthenticateOperator(fixture.auth, backupRaw)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := fixture.store.RevokeOperator(
		backup, fixture.admin.CredentialID, fixture.now.Add(3*time.Minute),
	); err != nil || !revoked {
		t.Fatalf("revoke detached operator = (%v, %v)", revoked, err)
	}
	if _, _, err := fixture.store.CreateTenant(
		fixture.admin, "tenant-after-revocation", fixture.now.Add(4*time.Minute),
	); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("detached revoked operator reached mutation: %v", err)
	}

	if _, revoked, err := fixture.store.RevokeNodeCredential(
		backup, node.CredentialID, fixture.now.Add(5*time.Minute),
	); err != nil || !revoked {
		t.Fatalf("revoke detached node = (%v, %v)", revoked, err)
	}
	if _, err := fixture.store.Poll(
		node, []string{}, fixture.now.Add(6*time.Minute), time.Minute, 1,
	); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("detached revoked node polled work: %v", err)
	}
	if _, err := fixture.store.ApplyReport(
		node, validMissingReport(), fixture.now.Add(6*time.Minute),
	); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("detached revoked node reported work: %v", err)
	}
}

func TestIssueOperatorRetrySurvivesReopenAndRevocationFencesIt(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	requestID := "operator-request-1"
	issuedRaw, issued, created, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, requestID, controlauth.RoleTenantOperator, "tenant-a", fixture.now.Add(time.Minute),
	)
	if err != nil || !created {
		t.Fatalf("first operator issuance = (%v, %v)", created, err)
	}
	assertBearerNotPersisted(t, fixture.dir, issuedRaw)
	retryRaw, retry, created, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, requestID, controlauth.RoleTenantOperator, "tenant-a", fixture.now.Add(2*time.Minute),
	)
	if err != nil || created || retryRaw != issuedRaw || !credentialsEqual(retry, issued) {
		t.Fatalf("operator retry = (same_raw=%v, same_record=%v, created=%v, err=%v)",
			retryRaw == issuedRaw, credentialsEqual(retry, issued), created, err)
	}
	if _, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, requestID, controlauth.RoleTenantOperator, "tenant-b", fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed operator scope error = %v", err)
	}
	if _, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, requestID, controlauth.RoleSiteAdmin, "", fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed operator role error = %v", err)
	}
	wrongAuth, err := controlauth.New(bytes.Repeat([]byte{32}, controlauth.KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := fixture.store.IssueOperator(
		fixture.admin, wrongAuth, requestID, controlauth.RoleTenantOperator, "tenant-a", fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("retry with a different auth key error = %v", err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	fixture.store = reopened
	retryRaw, retry, created, err = reopened.IssueOperator(
		fixture.admin, fixture.auth, requestID, controlauth.RoleTenantOperator, "tenant-a", fixture.now.Add(3*time.Minute),
	)
	if err != nil || created || retryRaw != issuedRaw || !credentialsEqual(retry, issued) {
		t.Fatalf("reopened operator retry = (same_raw=%v, same_record=%v, created=%v, err=%v)",
			retryRaw == issuedRaw, credentialsEqual(retry, issued), created, err)
	}
	nodeRaw, nodeIdentity := fixture.createNode(t, "tenant-a")
	if revoked, err := reopened.RevokeOperator(fixture.admin, nodeIdentity.CredentialID, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrNotFound) || revoked {
		t.Fatalf("operator endpoint revoked node credential = (%v, %v)", revoked, err)
	}
	if _, err := reopened.AuthenticateNode(fixture.auth, nodeRaw); err != nil {
		t.Fatalf("node credential changed after operator-only revoke: %v", err)
	}
	if revoked, err := reopened.RevokeOperator(fixture.admin, issued.ID, fixture.now.Add(4*time.Minute)); err != nil || !revoked {
		t.Fatalf("operator revoke = (%v, %v)", revoked, err)
	}
	if _, _, _, err := reopened.IssueOperator(
		fixture.admin, fixture.auth, requestID, controlauth.RoleTenantOperator, "tenant-a", fixture.now.Add(5*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked operator retry error = %v", err)
	}
	if revoked, err := reopened.RevokeCredential(fixture.admin, nodeIdentity.CredentialID, fixture.now.Add(5*time.Minute)); err != nil || !revoked {
		t.Fatalf("generic credential revoke = (%v, %v)", revoked, err)
	}
	if _, err := reopened.AuthenticateNode(fixture.auth, nodeRaw); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("generic revocation did not revoke node credential: %v", err)
	}
}

func TestConcurrentIssueOperatorCreatesOneRecoverableCredential(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	type issueResult struct {
		raw        string
		credential controlauth.Credential
		created    bool
		err        error
	}
	const callers = 16
	start := make(chan struct{})
	results := make(chan issueResult, callers)
	for range callers {
		go func() {
			<-start
			raw, credential, created, err := fixture.store.IssueOperator(
				fixture.admin, fixture.auth, "concurrent-operator-1", controlauth.RoleTenantOperator, "tenant-a", fixture.now.Add(time.Minute),
			)
			results <- issueResult{raw: raw, credential: credential, created: created, err: err}
		}()
	}
	close(start)
	createdCount := 0
	var expected issueResult
	for index := range callers {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent issue %d: %v", index, result.err)
		}
		if index == 0 {
			expected = result
		} else if result.raw != expected.raw || !credentialsEqual(result.credential, expected.credential) {
			t.Fatalf("concurrent issue %d returned a different credential", index)
		}
		if result.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent created count = %d, want 1", createdCount)
	}
}

func TestEnrollmentIssuanceRetrySurvivesReopenAndBindsIssuer(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	operatorRaw, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "tenant-a-operator", controlauth.RoleTenantOperator, "tenant-a", fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := fixture.store.AuthenticateOperator(fixture.auth, operatorRaw)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := fixture.now.Add(2 * time.Minute)
	raw, enrollment, _, created, err := fixture.store.CreateEnrollmentForRequest(
		operator, fixture.auth, "node-a-enrollment", "node-a", []string{"tenant-a"}, createdAt.Add(15*time.Minute), createdAt,
	)
	if err != nil || !created || enrollment.IssueRequestID != "node-a-enrollment" || enrollment.IssuerCredentialID != operator.CredentialID {
		t.Fatalf("first enrollment issuance = (%+v, %v, %v)", enrollment, created, err)
	}
	assertBearerNotPersisted(t, fixture.dir, raw)
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.store, err = Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.store.Close() })
	retryAt := createdAt.Add(time.Minute)
	retriedRaw, retried, _, created, err := fixture.store.CreateEnrollmentForRequest(
		operator, fixture.auth, "node-a-enrollment", "node-a", []string{"tenant-a"}, retryAt.Add(15*time.Minute), retryAt,
	)
	if err != nil || created || retriedRaw != raw || !enrollmentsEqual(retried, enrollment) {
		t.Fatalf("reopened enrollment retry = (same_raw=%v, same_record=%v, created=%v, err=%v)",
			retriedRaw == raw, enrollmentsEqual(retried, enrollment), created, err)
	}
	if _, _, _, _, err := fixture.store.CreateEnrollmentForRequest(
		operator, fixture.auth, "node-a-enrollment", "node-a", []string{"tenant-a"}, retryAt.Add(10*time.Minute), retryAt,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed enrollment retry error = %v", err)
	}
	otherRaw, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "tenant-a-operator-2", controlauth.RoleTenantOperator, "tenant-a", fixture.now.Add(3*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	other, err := fixture.store.AuthenticateOperator(fixture.auth, otherRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := fixture.store.CreateEnrollmentForRequest(
		other, fixture.auth, "node-a-enrollment", "node-a", []string{"tenant-a"}, retryAt.Add(15*time.Minute), retryAt,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("different operator recovered an existing-node enrollment: %v", err)
	}
}

func TestEnrollmentExchangePinsEvidenceAtomicallyAndSurvivesReopen(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	raw, enrollment, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, "node-1", []string{"tenant-a"}, fixture.now.Add(time.Hour), fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	private := newEvidencePrivateKey(t)
	proof := evidenceIdentityProof(t, fixture.auth, enrollment, private)
	before, err := fixture.store.Status()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := fixture.store.ExchangeEnrollment(
		fixture.auth, raw, "exchange-1", proof, fixture.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	after, err := fixture.store.Status()
	if err != nil {
		t.Fatal(err)
	}
	if after.Sequence != before.Sequence+1 || after.Credentials != before.Credentials+1 {
		t.Fatalf("exchange was not one atomic WAL transaction: before=%+v after=%+v", before, after)
	}
	node, found, err := fixture.store.GetNode(fixture.admin, "tenant-a", "node-1")
	if err != nil || !found || node.Evidence == nil {
		t.Fatalf("pinned node = (%+v, %v, %v)", node, found, err)
	}
	if node.Evidence.IdentityProof != proof || node.Evidence.Sequence != 0 ||
		node.Evidence.ChainHash != evidenceGenesisHash || node.Evidence.RecordsAccepted != 0 {
		t.Fatalf("pinned evidence witness = %+v", node.Evidence)
	}
	assertBearerNotPersisted(t, fixture.dir, credential.Credential)

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.store, err = Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.store.Close() })
	node, found, err = fixture.store.GetNode(fixture.admin, "tenant-a", "node-1")
	if err != nil || !found || node.Evidence == nil || node.Evidence.IdentityProof != proof {
		t.Fatalf("reopened witness = (%+v, %v, %v)", node.Evidence, found, err)
	}
	if _, err := fixture.store.AuthenticateNode(fixture.auth, credential.Credential); err != nil {
		t.Fatalf("reopened credential: %v", err)
	}
	retried, err := fixture.store.ExchangeEnrollment(
		fixture.auth, raw, "exchange-1", proof, fixture.now.Add(3*time.Minute),
	)
	if err != nil || retried != credential {
		t.Fatalf("reopened exact retry = (%+v, %v)", retried, err)
	}
	retriedStatus, err := fixture.store.Status()
	if err != nil || retriedStatus.Sequence != after.Sequence {
		t.Fatalf("exact retry appended a WAL record: status=%+v error=%v", retriedStatus, err)
	}
}

func TestEnrollmentEvidenceIdentityAllowsSameKeyCredentialRotation(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	private := newEvidencePrivateKey(t)
	firstRaw, firstEnrollment, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, "node-1", []string{"tenant-a"}, fixture.now.Add(time.Hour), fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstProof := evidenceIdentityProof(t, fixture.auth, firstEnrollment, private)
	firstCredential, err := fixture.store.ExchangeEnrollment(
		fixture.auth, firstRaw, "exchange-1", firstProof, fixture.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	rotatedRaw, rotatedEnrollment, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, "node-1", []string{"tenant-a"}, fixture.now.Add(2*time.Hour), fixture.now.Add(3*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	rotatedProof := evidenceIdentityProof(t, fixture.auth, rotatedEnrollment, private)
	rotatedCredential, err := fixture.store.ExchangeEnrollment(
		fixture.auth, rotatedRaw, "exchange-2", rotatedProof, fixture.now.Add(4*time.Minute),
	)
	if err != nil || rotatedCredential == firstCredential {
		t.Fatalf("same-key credential rotation = (%+v, %v)", rotatedCredential, err)
	}
	retried, err := fixture.store.ExchangeEnrollment(
		fixture.auth, rotatedRaw, "exchange-2", rotatedProof, fixture.now.Add(5*time.Minute),
	)
	if err != nil || retried != rotatedCredential {
		t.Fatalf("rotated credential retry = (%+v, %v)", retried, err)
	}
	node, found, err := fixture.store.GetNode(fixture.admin, "tenant-a", "node-1")
	if err != nil || !found || node.Evidence == nil || node.Evidence.IdentityProof != firstProof {
		t.Fatalf("rotation replaced original enrollment provenance: node=%+v found=%v error=%v", node, found, err)
	}

	conflictingRaw, conflictingEnrollment, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, "node-1", []string{"tenant-a"}, fixture.now.Add(3*time.Hour), fixture.now.Add(6*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	beforeRejected, err := fixture.store.Status()
	if err != nil {
		t.Fatal(err)
	}
	otherPrivate := newEvidencePrivateKey(t)
	conflicts := []controlprotocol.ExecutorEvidenceIdentityProofV1{
		evidenceIdentityProof(t, fixture.auth, conflictingEnrollment, otherPrivate),
		signedEvidenceIdentityProof(t, fixture.auth.InstanceID(), conflictingEnrollment.ID, "node-other", "node-other", 1, private),
		signedEvidenceIdentityProof(t, fixture.auth.InstanceID(), conflictingEnrollment.ID, "node-1", "node-1", 2, private),
		signedEvidenceIdentityProof(t, "control-other", conflictingEnrollment.ID, "node-1", "node-1", 1, private),
	}
	for index, conflict := range conflicts {
		if _, err := fixture.store.ExchangeEnrollment(
			fixture.auth, conflictingRaw, "exchange-3", conflict, fixture.now.Add(7*time.Minute),
		); !errors.Is(err, ErrConflict) {
			t.Fatalf("changed evidence identity %d error = %v", index, err)
		}
	}
	forged := evidenceIdentityProof(t, fixture.auth, conflictingEnrollment, private)
	forged.SignatureBase64 = strings.Repeat("A", len(forged.SignatureBase64))
	if _, err := fixture.store.ExchangeEnrollment(
		fixture.auth, conflictingRaw, "exchange-3", forged, fixture.now.Add(7*time.Minute),
	); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("forged evidence proof error = %v", err)
	}
	afterRejected, err := fixture.store.Status()
	if err != nil || afterRejected != beforeRejected {
		t.Fatalf("rejected evidence identities mutated state: before=%+v after=%+v error=%v", beforeRejected, afterRejected, err)
	}

	reusedRaw, reusedEnrollment, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, "node-2", []string{"tenant-a"}, fixture.now.Add(4*time.Hour), fixture.now.Add(8*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	reusedProof := evidenceIdentityProof(t, fixture.auth, reusedEnrollment, private)
	beforeReuse, err := fixture.store.Status()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ExchangeEnrollment(
		fixture.auth, reusedRaw, "exchange-4", reusedProof, fixture.now.Add(9*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-node receipt key reuse error = %v", err)
	}
	afterReuse, err := fixture.store.Status()
	if err != nil || afterReuse != beforeReuse {
		t.Fatalf("cross-node key rejection mutated state: before=%+v after=%+v error=%v", beforeReuse, afterReuse, err)
	}
}

func TestConcurrentEnrollmentExchangePinsOnlyOneReceiptKey(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	firstRaw, firstEnrollment, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, "node-1", []string{"tenant-a"}, fixture.now.Add(time.Hour), fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, secondEnrollment, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, "node-1", []string{"tenant-a"}, fixture.now.Add(2*time.Hour), fixture.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstProof := evidenceIdentityProof(t, fixture.auth, firstEnrollment, newEvidencePrivateKey(t))
	secondProof := evidenceIdentityProof(t, fixture.auth, secondEnrollment, newEvidencePrivateKey(t))
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, input := range []struct {
		raw       string
		requestID string
		proof     controlprotocol.ExecutorEvidenceIdentityProofV1
	}{
		{firstRaw, "exchange-1", firstProof},
		{secondRaw, "exchange-2", secondProof},
	} {
		input := input
		go func() {
			<-start
			_, err := fixture.store.ExchangeEnrollment(
				fixture.auth, input.raw, input.requestID, input.proof, fixture.now.Add(3*time.Minute),
			)
			results <- err
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("concurrent exchange error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent exchange outcomes = successes %d conflicts %d", successes, conflicts)
	}
	status, err := fixture.store.Status()
	if err != nil || status.Credentials != 2 {
		t.Fatalf("concurrent exchange credential count = (%+v, %v)", status, err)
	}
	node, found, err := fixture.store.GetNode(fixture.admin, "tenant-a", "node-1")
	if err != nil || !found || node.Evidence == nil {
		t.Fatalf("concurrent exchange witness = (%+v, %v, %v)", node, found, err)
	}
	if node.Evidence.PublicKeyDigest != firstProof.Claim.PublicKeySHA256 &&
		node.Evidence.PublicKeyDigest != secondProof.Claim.PublicKeySHA256 {
		t.Fatalf("concurrent exchange pinned an unknown receipt key: %+v", node.Evidence)
	}
}

func TestNodeCredentialRevocationIsNarrowAndIdempotent(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	raw, identity := fixture.createNode(t, "tenant-a")
	operator := controlauth.Identity{Role: controlauth.RoleTenantOperator, TenantID: "tenant-a"}
	if _, _, err := fixture.store.RevokeNodeCredential(operator, identity.CredentialID, fixture.now.Add(2*time.Minute)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant operator node-credential revocation error = %v", err)
	}
	if _, _, err := fixture.store.RevokeNodeCredential(fixture.admin, fixture.adminRecord.ID, fixture.now.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("node endpoint accepted an operator credential: %v", err)
	}
	nodeID, revoked, err := fixture.store.RevokeNodeCredential(fixture.admin, identity.CredentialID, fixture.now.Add(2*time.Minute))
	if err != nil || !revoked || nodeID != "node-1" {
		t.Fatalf("node credential revoke = (%q, %v, %v)", nodeID, revoked, err)
	}
	nodeID, revoked, err = fixture.store.RevokeNodeCredential(fixture.admin, identity.CredentialID, fixture.now.Add(3*time.Minute))
	if err != nil || revoked || nodeID != "node-1" {
		t.Fatalf("node credential revoke retry = (%q, %v, %v)", nodeID, revoked, err)
	}
	if _, err := fixture.store.AuthenticateNode(fixture.auth, raw); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("revoked node credential authentication = %v", err)
	}
	if node, found, err := fixture.store.GetNode(fixture.admin, "tenant-a", "node-1"); err != nil || !found || !node.Active {
		t.Fatalf("credential revocation disabled its node = (%+v, %v, %v)", node, found, err)
	}
}

func TestMultiTenantWorkflowFencesReportsAndRevokesCredentials(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	operatorRaw, operatorRecord, created, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "tenant-a-operator-1", controlauth.RoleTenantOperator, "tenant-a", fixture.now.Add(time.Minute),
	)
	if err != nil || !created {
		t.Fatalf("issue tenant operator = (%v, %v)", created, err)
	}
	operator, err := fixture.store.AuthenticateOperator(fixture.auth, operatorRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := fixture.store.CreateEnrollment(operator, fixture.auth, "forbidden-node", []string{"tenant-b"}, fixture.now.Add(time.Hour), fixture.now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant enrollment error = %v", err)
	}

	inputTenants := []string{"tenant-b", "tenant-a"}
	enrollmentRaw, enrollment, node, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, "node-1", inputTenants, fixture.now.Add(time.Hour), fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	inputTenants[0] = "changed"
	if !equalStrings(node.TenantIDs, []string{"tenant-a", "tenant-b"}) || !equalStrings(enrollment.TenantIDs, []string{"tenant-a", "tenant-b"}) {
		t.Fatalf("canonical bindings node=%v enrollment=%v", node.TenantIDs, enrollment.TenantIDs)
	}
	evidencePrivate := newEvidencePrivateKey(t)
	proof := evidenceIdentityProof(t, fixture.auth, enrollment, evidencePrivate)
	credentialFile, err := fixture.store.ExchangeEnrollment(fixture.auth, enrollmentRaw, "exchange-1", proof, fixture.now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := fixture.store.ExchangeEnrollment(fixture.auth, enrollmentRaw, "exchange-1", proof, fixture.now.Add(3*time.Minute))
	if err != nil || retry != credentialFile {
		t.Fatalf("deterministic exchange retry = (%+v, %v)", retry, err)
	}
	nodeIdentity, err := fixture.store.AuthenticateNode(fixture.auth, credentialFile.Credential)
	if err != nil || !controlauth.NodeAuthorizedTenant(nodeIdentity, "tenant-a") || !controlauth.NodeAuthorizedTenant(nodeIdentity, "tenant-b") {
		t.Fatalf("node identity = (%+v, %v)", nodeIdentity, err)
	}
	nodes, err := fixture.store.ListNodes(operator, "tenant-a")
	if err != nil || len(nodes) != 1 || !equalStrings(nodes[0].TenantIDs, []string{"tenant-a"}) {
		t.Fatalf("tenant-projected nodes = (%+v, %v)", nodes, err)
	}
	nodes[0].Capabilities = append(nodes[0].Capabilities, "mutated")
	storedNode, found, err := fixture.store.GetNode(fixture.admin, "tenant-a", "node-1")
	if err != nil || !found || len(storedNode.Capabilities) != 0 {
		t.Fatalf("node copy aliased state = (%+v, %v, %v)", storedNode, found, err)
	}
	if _, _, _, err := fixture.store.CreateEnrollment(
		operator, fixture.auth, "node-1", []string{"tenant-a"}, fixture.now.Add(2*time.Hour), fixture.now.Add(3*time.Minute),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant operator re-enrolled an existing global node: %v", err)
	}

	commandRaw := signedCommand(t, "command-1", "tenant-a", "node-1", 0)
	command, created, err := fixture.store.SubmitCommand(operator, "tenant-a", "node-1", commandRaw, fixture.now.Add(4*time.Minute))
	if err != nil || !created {
		t.Fatalf("submit command = (%+v, %v, %v)", command, created, err)
	}
	command.CommandDSSE[0] ^= 0xff
	storedCommand, found, err := fixture.store.GetCommand(operator, "tenant-a", "node-1", "command-1")
	if err != nil || !found || !bytes.Equal(storedCommand.CommandDSSE, commandRaw) {
		t.Fatal("returned command bytes alias retained state")
	}
	if _, created, err := fixture.store.SubmitCommand(operator, "tenant-a", "node-1", commandRaw, fixture.now.Add(5*time.Minute)); err != nil || created {
		t.Fatalf("exact command retry = (%v, %v)", created, err)
	}
	changedRaw := signedCommand(t, "command-1", "tenant-a", "node-1", 1)
	if _, _, err := fixture.store.SubmitCommand(operator, "tenant-a", "node-1", changedRaw, fixture.now.Add(5*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed command retry error = %v", err)
	}
	wrongRoute := signedCommand(t, "command-x", "tenant-b", "node-1", 0)
	if _, _, err := fixture.store.SubmitCommand(operator, "tenant-a", "node-1", wrongRoute, fixture.now.Add(5*time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("signed route mismatch error = %v", err)
	}

	first, err := fixture.store.Poll(nodeIdentity, []string{"multi-tenant", "delivery-leases-v3"}, fixture.now.Add(6*time.Minute), time.Minute, 128)
	if err != nil || len(first) != 1 || first[0].DeliveryGeneration != 1 {
		t.Fatalf("first poll = (%+v, %v)", first, err)
	}
	statusBefore, _ := fixture.store.Status()
	empty, err := fixture.store.Poll(nodeIdentity, []string{"delivery-leases-v3", "multi-tenant"}, fixture.now.Add(6*time.Minute+30*time.Second), time.Minute, 128)
	statusAfter, _ := fixture.store.Status()
	if err != nil || empty == nil || len(empty) != 0 || statusAfter.Sequence != statusBefore.Sequence {
		t.Fatalf("throttled poll = (%+v, %v), sequence %d -> %d", empty, err, statusBefore.Sequence, statusAfter.Sequence)
	}
	second, err := fixture.store.Poll(nodeIdentity, []string{"delivery-leases-v3", "multi-tenant"}, fixture.now.Add(8*time.Minute), time.Minute, 128)
	if err != nil || len(second) != 1 || second[0].DeliveryGeneration != 2 {
		t.Fatalf("reclaimed poll = (%+v, %v)", second, err)
	}
	stale := reportFor(first[0], controlprotocol.ExecutorStatusDone)
	if applied, err := fixture.store.ApplyReport(nodeIdentity, stale, fixture.now.Add(8*time.Minute)); err != nil || applied {
		t.Fatalf("stale report = (%v, %v)", applied, err)
	}
	report := reportFor(second[0], controlprotocol.ExecutorStatusDone)
	if applied, err := fixture.store.ApplyReport(nodeIdentity, report, fixture.now.Add(8*time.Minute)); err != nil || !applied {
		t.Fatalf("terminal report = (%v, %v)", applied, err)
	}
	if applied, err := fixture.store.ApplyReport(nodeIdentity, report, fixture.now.Add(9*time.Minute)); err != nil || applied {
		t.Fatalf("exact report retry = (%v, %v)", applied, err)
	}
	conflict := report
	conflict.Status = controlprotocol.ExecutorStatusFailed
	if _, err := fixture.store.ApplyReport(nodeIdentity, conflict, fixture.now.Add(9*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-generation conflicting report error = %v", err)
	}
	storedCommand, found, err = fixture.store.GetCommand(operator, "tenant-a", "node-1", "command-1")
	if err != nil || !found || storedCommand.State != CommandTerminal || storedCommand.Terminal.Report.Status != controlprotocol.ExecutorStatusDone {
		t.Fatalf("terminal command = (%+v, %v, %v)", storedCommand, found, err)
	}
	storedNode, found, err = fixture.store.GetNode(fixture.admin, "tenant-a", "node-1")
	if err != nil || !found || storedNode.LastSeenAt == "" || !equalStrings(storedNode.Capabilities, []string{"delivery-leases-v3", "multi-tenant"}) {
		t.Fatalf("node observation = (%+v, %v, %v)", storedNode, found, err)
	}

	if revoked, err := fixture.store.RevokeOperator(fixture.admin, operatorRecord.ID, fixture.now.Add(10*time.Minute)); err != nil || !revoked {
		t.Fatalf("operator revoke = (%v, %v)", revoked, err)
	}
	if _, err := fixture.store.AuthenticateOperator(fixture.auth, operatorRaw); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("revoked operator authentication = %v", err)
	}
	if revoked, err := fixture.store.RevokeNode(fixture.admin, "node-1", fixture.now.Add(11*time.Minute)); err != nil || revoked != 1 {
		t.Fatalf("node revoke = (%d, %v)", revoked, err)
	}
	if _, err := fixture.store.AuthenticateNode(fixture.auth, credentialFile.Credential); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("revoked node authentication = %v", err)
	}
}

func TestTenantQuotasPreserveOtherTenantWorkAndExpiredEnrollmentsReclaim(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCommands = 2
	limits.MaxCommandsPerTenant = 1
	limits.MaxCommandsPerNode = 1
	limits.MaxEnrollments = 1
	limits.MaxEnrollmentsPerTenant = 1
	fixture := newRecordsFixture(t, limits)
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	_, nodeIdentity := fixture.createNode(t, "tenant-a", "tenant-b")
	if _, _, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", signedCommand(t, "a-1", "tenant-a", "node-1", 0), fixture.now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", signedCommand(t, "a-2", "tenant-a", "node-1", 0), fixture.now.Add(2*time.Minute)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("tenant command quota error = %v", err)
	}
	if _, _, err := fixture.store.SubmitCommand(fixture.admin, "tenant-b", "node-1", signedCommand(t, "b-1", "tenant-b", "node-1", 0), fixture.now.Add(2*time.Minute)); err != nil {
		t.Fatalf("tenant B reservation was displaced: %v", err)
	}
	deliveries, err := fixture.store.Poll(nodeIdentity, []string{}, fixture.now.Add(3*time.Minute), time.Minute, 128)
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("preserved unsettled deliveries = (%d, %v)", len(deliveries), err)
	}

	// The consumed fixture enrollment expires at +1h. A later creation reclaims
	// it before applying the one-record enrollment quota.
	if _, _, _, err := fixture.store.CreateEnrollment(fixture.admin, fixture.auth, "node-2", []string{"tenant-a"}, fixture.now.Add(3*time.Hour), fixture.now.Add(2*time.Hour)); err != nil {
		t.Fatalf("expired enrollment did not reclaim capacity: %v", err)
	}
	if status, err := fixture.store.Status(); err != nil || status.Enrollments != 1 {
		t.Fatalf("reclaimed enrollment status = (%+v, %v)", status, err)
	}
}

func TestTerminalRetentionPrunesOnlyKnownSettledOutcomes(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCommands = 1
	limits.MaxCommandsPerTenant = 1
	limits.MaxCommandsPerNode = 1
	limits.TerminalRetention = time.Hour
	fixture := newRecordsFixture(t, limits)
	fixture.createTenant(t, "tenant-a")
	_, nodeIdentity := fixture.createNode(t, "tenant-a")
	firstRaw := signedCommand(t, "first", "tenant-a", "node-1", 0)
	if _, _, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", firstRaw, fixture.now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.store.Poll(nodeIdentity, []string{}, fixture.now.Add(3*time.Minute), time.Minute, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("poll first = (%v, %v)", len(first), err)
	}
	if applied, err := fixture.store.ApplyReport(nodeIdentity, reportFor(first[0], controlprotocol.ExecutorStatusDone), fixture.now.Add(4*time.Minute)); err != nil || !applied {
		t.Fatalf("settle first = (%v, %v)", applied, err)
	}
	secondRaw := signedCommand(t, "second", "tenant-a", "node-1", 0)
	if _, _, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", secondRaw, fixture.now.Add(30*time.Minute)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("young terminal was pruned early: %v", err)
	}
	if _, _, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", secondRaw, fixture.now.Add(2*time.Hour)); err != nil {
		t.Fatalf("old terminal was not pruned: %v", err)
	}
	if _, found, err := fixture.store.GetCommand(fixture.admin, "tenant-a", "node-1", "first"); err != nil || found {
		t.Fatalf("pruned first command = (%v, %v)", found, err)
	}
	second, err := fixture.store.Poll(nodeIdentity, []string{}, fixture.now.Add(2*time.Hour+time.Minute), time.Minute, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("poll second = (%v, %v)", len(second), err)
	}
	unknown := reportFor(second[0], controlprotocol.ExecutorStatusOutcomeUnknown)
	if applied, err := fixture.store.ApplyReport(nodeIdentity, unknown, fixture.now.Add(2*time.Hour+2*time.Minute)); err != nil || !applied {
		t.Fatalf("unknown outcome = (%v, %v)", applied, err)
	}
	thirdRaw := signedCommand(t, "third", "tenant-a", "node-1", 0)
	if _, _, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", thirdRaw, fixture.now.Add(5*time.Hour)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("unknown outcome was evicted: %v", err)
	}
}

func TestObservedRenewalUsesBoundedRetentionInsteadOfExhaustingCourier(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCommands = 1
	limits.MaxCommandsPerTenant = 1
	limits.MaxCommandsPerNode = 1
	limits.TerminalRetention = time.Hour
	fixture := newRecordsFixture(t, limits)
	fixture.createTenant(t, "tenant-a")
	_, nodeIdentity := fixture.createNode(t, "tenant-a")
	raw := signedRenewCommand(t, "renew-first", "tenant-a", "node-1")
	if _, _, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-a", "node-1", raw, fixture.now,
	); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.store.Poll(nodeIdentity, []string{}, fixture.now, time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll renewal = (%d, %v)", len(deliveries), err)
	}
	if applied, err := fixture.store.ApplyReport(
		nodeIdentity,
		reportFor(deliveries[0], controlprotocol.ExecutorStatusDone),
		fixture.now,
	); err != nil || !applied {
		t.Fatalf("settle renewal = (%v, %v)", applied, err)
	}
	second := signedCommand(t, "after-renew", "tenant-a", "node-1", 0)
	if _, _, err := fixture.store.SubmitCommand(
		fixture.admin,
		"tenant-a",
		"node-1",
		second,
		fixture.now.Add(admission.MaxWorkloadLeaseDuration+admission.CommandClockSkew+time.Second),
	); err != nil {
		t.Fatalf("settled renewal exhausted command inventory: %v", err)
	}
}

func TestNearLimitCommandFitsEncodedPollResponseIncludingNewline(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, nodeIdentity := fixture.createNode(t, "tenant-a")
	raw := signedCommand(t, "large", "tenant-a", "node-1", 500_000)
	if _, _, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", raw, fixture.now.Add(2*time.Minute)); err != nil {
		t.Fatalf("submit near-limit command (%d bytes): %v", len(raw), err)
	}
	deliveries, err := fixture.store.Poll(nodeIdentity, []string{}, fixture.now.Add(3*time.Minute), time.Minute, 128)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll near-limit command = (%d, %v)", len(deliveries), err)
	}
	rawDeliveries := make([]json.RawMessage, len(deliveries))
	for index, delivery := range deliveries {
		rawDeliveries[index], err = json.Marshal(delivery)
		if err != nil {
			t.Fatal(err)
		}
	}
	response, err := json.Marshal(controlprotocol.ExecutorPollResponseV3{ProtocolVersion: controlprotocol.ExecutorProtocolV3, Deliveries: rawDeliveries})
	if err != nil {
		t.Fatal(err)
	}
	if len(response)+1 > maxPollResponseBytes || len(response) < 800_000 {
		t.Fatalf("encoded response with HTTP newline = %d bytes", len(response)+1)
	}
	if !pollResponseFits(deliveries, controlprotocol.ExecutorProtocolV3) {
		t.Fatal("accepted delivery no longer fits the exact response encoder cap")
	}
}

func TestPollResponseFitCountsEncoderNewlineAtExactBoundary(t *testing.T) {
	delivery := controlprotocol.ExecutorDeliveryV3{
		DeliveryID: "delivery", DeliveryGeneration: 1, CommandID: "command",
		CommandDigest: "sha256:" + strings.Repeat("a", 64), CommandDSSEBase64: "",
	}
	baseRaw, err := json.Marshal(controlprotocol.ExecutorPollResponseV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		Deliveries:      []json.RawMessage{mustJSON(t, delivery)},
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery.CommandDSSEBase64 = strings.Repeat("A", maxPollResponseBytes-1-len(baseRaw))
	exactRaw, err := json.Marshal(controlprotocol.ExecutorPollResponseV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		Deliveries:      []json.RawMessage{mustJSON(t, delivery)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(exactRaw)+1 != maxPollResponseBytes ||
		!pollResponseFits([]controlprotocol.ExecutorDeliveryV3{delivery}, controlprotocol.ExecutorProtocolV3) {
		t.Fatalf("exact boundary response = %d bytes including newline", len(exactRaw)+1)
	}
	delivery.CommandDSSEBase64 += "A"
	if pollResponseFits([]controlprotocol.ExecutorDeliveryV3{delivery}, controlprotocol.ExecutorProtocolV3) {
		t.Fatal("response one byte beyond the encoder cap was accepted")
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertBearerNotPersisted(t *testing.T, directory, bearer string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(bearer)) {
			t.Fatalf("bearer was persisted in control artifact %s", entry.Name())
		}
	}
}

func signedCommand(t *testing.T, commandID, tenantID, nodeID string, padding int) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{}`)
	if padding > 0 {
		encoded, err := json.Marshal(map[string]string{"padding": strings.Repeat("x", padding)})
		if err != nil {
			t.Fatal(err)
		}
		payload = encoded
	}
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2, CommandID: commandID, TenantID: tenantID, NodeID: nodeID,
		InstanceID: "agent-1", RuntimeRef: "uplink:6:node-1:agent-1", Kind: "start", ClaimGeneration: 1,
		InstanceGeneration: 1, CommandSequence: 1, IssuedAt: "2026-07-13T12:00:00Z",
		ExpiresAt: "2026-07-13T13:00:00Z", Payload: payload,
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(admission.CommandPayloadType, statementRaw, "tenant-key", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signedRenewCommand(t *testing.T, commandID, tenantID, nodeID string) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	payload, err := json.Marshal(admission.WorkloadLease{
		SchemaVersion: admission.WorkloadLeaseSchemaV1,
		ExpiresAt:     issued.Add(admission.MaxWorkloadLeaseDuration).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2, CommandID: commandID, TenantID: tenantID, NodeID: nodeID,
		InstanceID: "agent-1", RuntimeRef: "uplink:6:node-1:agent-1", Kind: "renew", ClaimGeneration: 1,
		InstanceGeneration: 1, CommandSequence: 1, IssuedAt: issued.Format(time.RFC3339Nano),
		ExpiresAt: issued.Add(admission.MaxWorkloadLeaseDuration).Format(time.RFC3339Nano), Payload: payload,
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(admission.CommandPayloadType, statementRaw, "tenant-key", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func reportFor(delivery controlprotocol.ExecutorDeliveryV3, status string) controlprotocol.ExecutorReportV3 {
	return controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3, DeliveryID: delivery.DeliveryID,
		DeliveryGeneration: delivery.DeliveryGeneration, CommandID: delivery.CommandID,
		CommandDigest: delivery.CommandDigest, Status: status, ReportedStatus: "completed", ClaimGeneration: 1,
	}
}
