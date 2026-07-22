package poolmembership

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestMembershipRoundTripAndBoundaries(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := Statement{
		SchemaVersion: 1, ControllerInstanceID: "control-a", PoolID: "pool-a", PoolRevision: 3,
		NodeID: "node-a", TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		BootIdentitySHA256:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SchedulingPolicySHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IssuedAt:               now.Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	raw, err := Sign(statement, "pool-authority-1", private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(raw, "pool-authority-1", public, now.Add(time.Minute))
	if err != nil || verified.Statement.NodeID != "node-a" || verified.Digest == "" || verified.KeyID != "pool-authority-1" {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	if _, err := Verify(raw, "pool-authority-1", public, now.Add(time.Hour)); err == nil {
		t.Fatal("expired membership was accepted")
	}
	statement.NotAfter = now.Add(MaxLifetime + time.Second).Format(time.RFC3339Nano)
	if _, err := Sign(statement, "pool-authority-1", private); err == nil {
		t.Fatal("overlong membership was signed")
	}
}
