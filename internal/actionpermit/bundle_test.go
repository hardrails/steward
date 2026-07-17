package actionpermit

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

func TestVerifyV4ReturnsExactBundleBindings(t *testing.T) {
	public, private := testKey(t)
	bundle := validBundleStatement()
	bundle.ApprovalThreshold = 1
	raw := signBundle(t, bundle, "authority-a", private)

	verified, err := Verify(raw, map[string]ed25519.PublicKey{"authority-a": public}, testNow, 5*time.Minute)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Bundle == nil || !reflect.DeepEqual(*verified.Bundle, bundle) {
		t.Fatalf("bundle mismatch:\n got: %#v\nwant: %#v", verified.Bundle, bundle)
	}
	if verified.Statement != (Statement{}) {
		t.Fatalf("V4 populated legacy statement: %#v", verified.Statement)
	}
	if verified.PayloadType != PayloadTypeV4 || !verified.Complete || verified.KeyID != "authority-a" ||
		!slices.Equal(verified.KeyIDs, []string{"authority-a"}) || verified.EnvelopeDigest != dsse.Digest(raw) {
		t.Fatalf("unexpected verified metadata: %#v", verified)
	}
}

func TestVerifyV4RequiresCanonicalDistinctApprovalThreshold(t *testing.T) {
	publicA, privateA := testKey(t)
	publicB, privateB := testKey(t)
	bundle := validBundleStatement()
	payload := mustJSON(t, bundle)
	first, err := dsse.Sign(PayloadTypeV4, payload, "authority-b", privateB)
	if err != nil {
		t.Fatal(err)
	}
	partialRaw, err := dsse.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{"authority-a": publicA, "authority-b": publicB}
	partial, err := VerifyPartial(partialRaw, trusted, testNow, 5*time.Minute)
	if err != nil || partial.Complete || partial.Bundle == nil || len(partial.KeyIDs) != 1 || partial.KeyIDs[0] != "authority-b" {
		t.Fatalf("partial verification = (%+v, %v)", partial, err)
	}
	if _, err := Verify(partialRaw, trusted, testNow, 5*time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("incomplete bundle error = %v", err)
	}

	completeEnvelope, err := dsse.AddSignature(first, "authority-a", privateA)
	if err != nil {
		t.Fatal(err)
	}
	completeRaw, err := dsse.Marshal(completeEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := Verify(completeRaw, trusted, testNow, 5*time.Minute)
	if err != nil || !complete.Complete || !slices.Equal(complete.KeyIDs, []string{"authority-a", "authority-b"}) {
		t.Fatalf("complete verification = (%+v, %v)", complete, err)
	}

	extraPublic, extraPrivate := testKey(t)
	withExtra, err := dsse.AddSignature(completeEnvelope, "authority-c", extraPrivate)
	if err != nil {
		t.Fatal(err)
	}
	withExtraRaw, err := dsse.Marshal(withExtra)
	if err != nil {
		t.Fatal(err)
	}
	trusted["authority-c"] = extraPublic
	if _, err := VerifyPartial(withExtraRaw, trusted, testNow, 5*time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-threshold bundle error = %v", err)
	}
}

func TestVerifyV4RejectsInvalidBundleStatements(t *testing.T) {
	public, private := testKey(t)
	trusted := map[string]ed25519.PublicKey{"authority-a": public}
	digest := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name   string
		mutate func(*BundleStatement)
	}{
		{"schema", func(b *BundleStatement) { b.SchemaVersion = SchemaV3 }},
		{"effect mode", func(b *BundleStatement) { b.EffectMode = "optional" }},
		{"threshold zero", func(b *BundleStatement) { b.ApprovalThreshold = 0 }},
		{"threshold over maximum", func(b *BundleStatement) { b.ApprovalThreshold = MaxBundleSteps + 1 }},
		{"empty node", func(b *BundleStatement) { b.NodeID = "" }},
		{"tenant NUL", func(b *BundleStatement) { b.TenantID = "tenant\x00a" }},
		{"instance too long", func(b *BundleStatement) { b.InstanceID = strings.Repeat("a", 257) }},
		{"generation zero", func(b *BundleStatement) { b.Generation = 0 }},
		{"capsule digest", func(b *BundleStatement) { b.CapsuleDigest = "SHA256:" + strings.Repeat("a", 64) }},
		{"policy digest", func(b *BundleStatement) { b.PolicyDigest = digest + "a" }},
		{"route policy digest", func(b *BundleStatement) { b.RoutePolicyDigest = "" }},
		{"bundle slash", func(b *BundleStatement) { b.BundleID = "deploy/prod" }},
		{"no steps", func(b *BundleStatement) { b.Steps = nil }},
		{"too many steps", func(b *BundleStatement) {
			step := b.Steps[0]
			b.Steps = make([]BundleStep, MaxBundleSteps+1)
			for index := range b.Steps {
				b.Steps[index] = step
				b.Steps[index].StepID = "step." + string(rune('a'+index))
				b.Steps[index].TaskID = "task." + string(rune('a'+index))
			}
		}},
		{"unsorted steps", func(b *BundleStatement) { b.Steps[0], b.Steps[1] = b.Steps[1], b.Steps[0] }},
		{"duplicate step", func(b *BundleStatement) { b.Steps[1].StepID = b.Steps[0].StepID }},
		{"duplicate task", func(b *BundleStatement) { b.Steps[1].TaskID = b.Steps[0].TaskID }},
		{"step slash", func(b *BundleStatement) { b.Steps[0].StepID = "step/one" }},
		{"connector slash", func(b *BundleStatement) { b.Steps[0].ConnectorID = "tickets/create" }},
		{"operation control", func(b *BundleStatement) { b.Steps[0].OperationID = "read\nnow" }},
		{"task leading dash", func(b *BundleStatement) { b.Steps[0].TaskID = "-task" }},
		{"operation digest", func(b *BundleStatement) { b.Steps[0].OperationDigest = "" }},
		{"request digest", func(b *BundleStatement) { b.Steps[0].RequestDigest = "sha256:" + strings.Repeat("g", 64) }},
		{"negative bytes", func(b *BundleStatement) { b.Steps[0].RequestBytes = -1 }},
		{"oversize request", func(b *BundleStatement) { b.Steps[0].RequestBytes = MaxRequestBytes + 1 }},
		{"content type parameter", func(b *BundleStatement) { b.Steps[0].ContentType = "application/json; charset=utf-8" }},
		{"bodyless with bytes", func(b *BundleStatement) { b.Steps[0].ContentType = "" }},
		{"JSON without bytes", func(b *BundleStatement) {
			b.Steps[0].RequestBytes = 0
			b.Steps[0].RequestDigest = RequestDigest(nil)
		}},
		{"fractional not before", func(b *BundleStatement) { b.NotBefore = "2026-07-13T11:59:00.000Z" }},
		{"offset expiry", func(b *BundleStatement) { b.ExpiresAt = "2026-07-13T12:04:00+00:00" }},
		{"empty interval", func(b *BundleStatement) { b.ExpiresAt = b.NotBefore }},
		{"not yet valid", func(b *BundleStatement) { b.NotBefore = "2026-07-13T12:00:01Z" }},
		{"expired", func(b *BundleStatement) { b.ExpiresAt = "2026-07-13T12:00:00Z" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := cloneBundle(validBundleStatement())
			test.mutate(&bundle)
			raw := signBundle(t, bundle, "authority-a", private)
			if _, err := VerifyPartial(raw, trusted, testNow, 5*time.Minute); !errors.Is(err, ErrInvalid) {
				t.Fatalf("VerifyPartial error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestVerifyV4RejectsJSONAndVersionAmbiguity(t *testing.T) {
	public, private := testKey(t)
	trusted := map[string]ed25519.PublicKey{"authority-a": public}
	bundle := validBundleStatement()
	bundle.ApprovalThreshold = 1
	payload := mustJSON(t, bundle)
	singlePayload := mustJSON(t, validAuthorizedStatement())

	unknownTop := append(append([]byte(nil), payload[:len(payload)-1]...), []byte(`,"extra":true}`)...)
	missingSteps := bytes.Replace(payload, []byte(`,"steps":`+string(mustJSON(t, bundle.Steps))), nil, 1)
	nullSteps := bytes.Replace(payload, []byte(`"steps":`+string(mustJSON(t, bundle.Steps))), []byte(`"steps":null`), 1)
	duplicateBundleID := bytes.Replace(payload, []byte(`"bundle_id":"bundle.release"`),
		[]byte(`"bundle_id":"bundle.release","bundle_id":"bundle.release"`), 1)
	unknownStep := bytes.Replace(payload, []byte(`"step_id":"01.ticket"`),
		[]byte(`"step_id":"01.ticket","extra":true`), 1)
	missingRequestBytes := bytes.Replace(payload, []byte(`,"request_bytes":16`), nil, 1)
	nullRequestBytes := bytes.Replace(payload, []byte(`"request_bytes":16`), []byte(`"request_bytes":null`), 1)
	duplicateStepID := bytes.Replace(payload, []byte(`"step_id":"01.ticket"`),
		[]byte(`"step_id":"01.ticket","step_id":"01.ticket"`), 1)

	for _, test := range []struct {
		name        string
		payloadType string
		payload     []byte
	}{
		{"unknown top-level member", PayloadTypeV4, unknownTop},
		{"missing steps", PayloadTypeV4, missingSteps},
		{"null steps", PayloadTypeV4, nullSteps},
		{"duplicate bundle ID", PayloadTypeV4, duplicateBundleID},
		{"unknown step member", PayloadTypeV4, unknownStep},
		{"missing zero-capable step member", PayloadTypeV4, missingRequestBytes},
		{"null step member", PayloadTypeV4, nullRequestBytes},
		{"duplicate step member", PayloadTypeV4, duplicateStepID},
		{"bundle payload under V3", PayloadTypeV3, payload},
		{"single payload under V4", PayloadTypeV4, singlePayload},
		{"unknown future payload type", "application/vnd.steward.action-permit.v5+json", payload},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := signPayload(t, test.payloadType, test.payload, "authority-a", private)
			if _, err := VerifyPartial(raw, trusted, testNow, 5*time.Minute); !errors.Is(err, ErrInvalid) {
				t.Fatalf("VerifyPartial error = %v, want ErrInvalid", err)
			}
		})
	}
}

func validBundleStatement() BundleStatement {
	request := []byte(`{"title":"help"}`)
	return BundleStatement{
		SchemaVersion: SchemaV4, EffectMode: EffectModeAuthorized, ApprovalThreshold: 2,
		NodeID: "node/a", TenantID: "tenant-a", InstanceID: "instance/a", Generation: 7,
		CapsuleDigest: "sha256:" + strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		RoutePolicyDigest: "sha256:" + strings.Repeat("c", 64), BundleID: "bundle.release",
		Steps: []BundleStep{
			{StepID: "01.ticket", ConnectorID: "tickets.create", OperationID: "issues.create",
				OperationDigest: "sha256:" + strings.Repeat("d", 64), TaskID: "task.ticket",
				RequestDigest: RequestDigest(request), RequestBytes: int64(len(request)), ContentType: "application/json"},
			{StepID: "02.notify", ConnectorID: "notify.send", OperationID: "release.complete",
				OperationDigest: "sha256:" + strings.Repeat("e", 64), TaskID: "task.notify",
				RequestDigest: RequestDigest(nil), RequestBytes: 0, ContentType: ""},
		},
		NotBefore: "2026-07-13T11:59:00Z", ExpiresAt: "2026-07-13T12:04:00Z",
	}
}

func cloneBundle(bundle BundleStatement) BundleStatement {
	bundle.Steps = append([]BundleStep(nil), bundle.Steps...)
	return bundle
}

func signBundle(t *testing.T, bundle BundleStatement, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	return signPayload(t, PayloadTypeV4, mustJSON(t, bundle), keyID, private)
}
