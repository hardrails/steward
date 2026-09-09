package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/interactionpermit"
)

func issuerResponse(f *taskCLIFixture) responseIssuerRequest {
	q := controlprotocol.InteractionRequestV1{
		SchemaVersion: controlprotocol.InteractionRequestSchemaV1, IdempotencyKey: "question-1", Source: "agent",
		TenantID: f.intent.TenantID, NodeID: f.intent.NodeID, InstanceID: f.intent.InstanceID,
		Generation: f.intent.Generation, RuntimeRef: f.admitted.RuntimeRef, GrantID: f.admitted.GrantID,
		CapsuleDigest: f.admitted.CapsuleDigest, PolicyDigest: f.admitted.PolicyDigest,
		Kind: "question", Title: "Which account?", Prompt: "Choose the account to inspect.",
		Options: []string{"cafe\u0301", "other"}, AllowText: true, TaskID: "issuer-task-1", RunID: "run-1",
		ObservedAt: f.now.Add(-time.Second).Format(time.RFC3339), AcceptedAt: f.now.Format(time.RFC3339Nano),
		ExpiresAt: f.now.Add(time.Hour).Format(time.RFC3339),
	}
	refreshIssuerQuestion(&q)
	return responseIssuerRequest{q, base64.StdEncoding.EncodeToString([]byte("{\n\"schema_version\":\"steward.interaction-response-body.v1\",\"choice\":\"café\",\"text\":\"Only read <&>\"}\n"))}
}

func refreshIssuerQuestion(q *controlprotocol.InteractionRequestV1) {
	digest := sha256.Sum256([]byte("steward-interaction-v1\x00" + q.GrantID + "\x00" + q.IdempotencyKey))
	q.InteractionID = "interaction-" + hex.EncodeToString(digest[:])
	q.RequestDigest = controlprotocol.InteractionRequestDigest(*q)
}

func TestResponseIssuerRetainsExactAnswerAcrossRestartAndExpiry(t *testing.T) {
	f, config := newTaskIssuerFixture(t)
	config.AllowResponses = true
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	request := issuerResponse(f)
	first, err := issuer.issueResponse(request)
	if err != nil {
		t.Fatal(err)
	}
	public, err := readPublicKey(f.publicPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := interactionpermit.Verify(first, map[string]ed25519.PublicKey{f.keyID: public}, f.now, config.Validity)
	if err != nil {
		t.Fatal(err)
	}
	response, _ := base64.StdEncoding.DecodeString(request.ResponseBase64)
	if verified.Statement.ResponseDigest != interactionpermit.ResponseDigest(response) ||
		verified.Statement.ResponseBytes != int64(len(response)) ||
		verified.Statement.RequestDigest != request.Interaction.RequestDigest ||
		verified.Statement.RuntimeRef != f.admitted.RuntimeRef {
		t.Fatal("response signature did not bind the original bytes and runtime")
	}
	if err = issuer.Close(); err != nil {
		t.Fatal(err)
	}
	issuer, err = openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	replay, err := issuer.issueResponse(request)
	if err != nil || !bytes.Equal(first, replay) || issuer.count != 1 {
		t.Fatalf("changed replay: %v", err)
	}
	// Equal string IDs still occupy disjoint task and response record namespaces.
	task := issuerRequest(f)
	task.TaskID = request.Interaction.InteractionID
	if _, err = issuer.issue(task); err != nil || issuer.count != 2 {
		t.Fatalf("task/response collision: %v", err)
	}
	request.Interaction.IdempotencyKey = "question-2"
	refreshIssuerQuestion(&request.Interaction)
	if _, err = issuer.issueResponse(request); !errors.Is(err, errTaskIssuerCapacity) {
		t.Fatalf("unbounded capacity: %v", err)
	}
	previousNow := timeNow
	timeNow = func() time.Time { return f.now.Add(10 * time.Minute) }
	defer func() { timeNow = previousNow }()
	if _, err = issuer.issueResponse(issuerResponse(f)); !errors.Is(err, errTaskIssuerConflict) {
		t.Fatalf("expired answer was renewed: %v", err)
	}
}

func TestResponseIssuerRejectsChangedAnswerOrQuestionWithoutReplacement(t *testing.T) {
	f, config := newTaskIssuerFixture(t)
	config.AllowResponses = true
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	request := issuerResponse(f)
	first, err := issuer.issueResponse(request)
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.ResponseBase64 = base64.StdEncoding.EncodeToString([]byte(`{"schema_version":"steward.interaction-response-body.v1","choice":"other"}`))
	if _, err = issuer.issueResponse(changed); !errors.Is(err, errTaskIssuerConflict) {
		t.Fatalf("changed answer signed: %v", err)
	}
	changed = request
	changed.Interaction.Prompt = "A different question"
	refreshIssuerQuestion(&changed.Interaction)
	if _, err = issuer.issueResponse(changed); !errors.Is(err, errTaskIssuerConflict) {
		t.Fatalf("changed question signed: %v", err)
	}
	replay, err := issuer.issueResponse(request)
	if err != nil || !bytes.Equal(first, replay) || issuer.count != 1 {
		t.Fatalf("original answer lost: %v", err)
	}
}

func TestResponseIssuerRefusesUnpinnedIdentitiesAndInvalidContent(t *testing.T) {
	for name, edit := range map[string]func(*responseIssuerRequest){
		"tenant":      func(r *responseIssuerRequest) { r.Interaction.TenantID = "foreign" },
		"node":        func(r *responseIssuerRequest) { r.Interaction.NodeID = "foreign" },
		"instance":    func(r *responseIssuerRequest) { r.Interaction.InstanceID = "foreign" },
		"generation":  func(r *responseIssuerRequest) { r.Interaction.Generation++ },
		"runtime":     func(r *responseIssuerRequest) { r.Interaction.RuntimeRef = "executor-" + strings.Repeat("f", 64) },
		"grant":       func(r *responseIssuerRequest) { r.Interaction.GrantID = "grant-" + strings.Repeat("f", 64) },
		"capsule":     func(r *responseIssuerRequest) { r.Interaction.CapsuleDigest = "sha256:" + strings.Repeat("f", 64) },
		"policy":      func(r *responseIssuerRequest) { r.Interaction.PolicyDigest = "sha256:" + strings.Repeat("f", 64) },
		"not-offered": func(r *responseIssuerRequest) { r.Interaction.Options = []string{"different"} },
		"no-text":     func(r *responseIssuerRequest) { r.Interaction.AllowText = false },
		"expired": func(r *responseIssuerRequest) {
			r.Interaction.AcceptedAt = "2020-01-01T00:00:00Z"
			r.Interaction.ObservedAt = r.Interaction.AcceptedAt
			r.Interaction.ExpiresAt = "2020-01-01T01:00:00Z"
		},
		"base64": func(r *responseIssuerRequest) { r.ResponseBase64 += "\n" },
		"oversize": func(r *responseIssuerRequest) {
			r.ResponseBase64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 4097))
		},
		"duplicate": func(r *responseIssuerRequest) {
			r.ResponseBase64 = base64.StdEncoding.EncodeToString([]byte(`{"schema_version":"steward.interaction-response-body.v1","choice":"other","choice":"other"}`))
		},
		"unknown": func(r *responseIssuerRequest) {
			r.ResponseBase64 = base64.StdEncoding.EncodeToString([]byte(`{"schema_version":"steward.interaction-response-body.v1","choice":"other","key":"secret"}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, config := newTaskIssuerFixture(t)
			config.AllowResponses = true
			issuer, err := openTaskIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			defer issuer.Close()
			r := issuerResponse(f)
			edit(&r)
			refreshIssuerQuestion(&r.Interaction)
			if _, err = issuer.issueResponse(r); err == nil || issuer.count != 0 {
				t.Fatalf("invalid request signed: %v", err)
			}
		})
	}
}

func TestResponseIssuerOptInIsBoundToStoreAndBusyIsBounded(t *testing.T) {
	f, config := newTaskIssuerFixture(t)
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = issuer.issueResponse(issuerResponse(f)); err == nil {
		t.Fatal("task-only station signed a response")
	}
	if err = issuer.Close(); err != nil {
		t.Fatal(err)
	}
	config.AllowResponses = true
	if other, err := openTaskIssuer(config); err == nil {
		_ = other.Close()
		t.Fatal("restart silently expanded authority")
	}
	config.Store = filepath.Join(f.directory, "response-store")
	if err = os.Mkdir(config.Store, 0o700); err != nil {
		t.Fatal(err)
	}
	issuer, err = openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	issuer.mu.Lock()
	_, err = issuer.issueResponse(issuerResponse(f))
	issuer.mu.Unlock()
	if !errors.Is(err, errTaskIssuerBusy) {
		t.Fatalf("busy signer accepted answer: %v", err)
	}
	if err = issuer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = issuer.issueResponse(issuerResponse(f)); !errors.Is(err, errTaskIssuerBusy) {
		t.Fatalf("closed signer accepted answer: %v", err)
	}
}

func TestResponseIssuerDoesNotReplaceAmbiguousOrForeignRetainedPermits(t *testing.T) {
	for _, scenario := range []string{"partial", "permissions", "symlink", "foreign-runtime"} {
		t.Run(scenario, func(t *testing.T) {
			f, config := newTaskIssuerFixture(t)
			config.AllowResponses = true
			issuer, err := openTaskIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			defer issuer.Close()
			request := issuerResponse(f)
			raw, err := issuer.issueResponse(request)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte("\x00interaction-response\x00" + request.Interaction.InteractionID))
			path := filepath.Join(config.Store, hex.EncodeToString(digest[:])+".json")
			switch scenario {
			case "partial":
				err = os.WriteFile(path, []byte("partial"), 0o600)
			case "permissions":
				err = os.Chmod(path, 0o644)
			case "symlink":
				err = os.Rename(path, path+".retained")
				if err == nil {
					err = os.Symlink(filepath.Join(f.directory, "absent"), path)
				}
			case "foreign-runtime":
				verified, verifyErr := interactionpermit.Verify(raw, map[string]ed25519.PublicKey{f.keyID: issuer.public}, f.now, config.Validity)
				if verifyErr != nil {
					t.Fatal(verifyErr)
				}
				private, readErr := readPrivateKey(f.privatePath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				defer clear(private)
				verified.Statement.RuntimeRef = "executor-" + strings.Repeat("f", 64)
				foreign, signErr := interactionpermit.Sign(verified.Statement, f.keyID, private)
				if signErr != nil {
					t.Fatal(signErr)
				}
				err = os.WriteFile(path, foreign, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if _, err = issuer.issueResponse(request); !errors.Is(err, errTaskIssuerConflict) {
					t.Fatalf("unsafe replay accepted: %v", err)
				}
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || issuer.count != 1 {
				t.Fatalf("ambiguous retained authority was changed: %v", err)
			}
		})
	}
}

func TestResponseIssuerCapsValidityAtQuestionExpiryAndRejectsDigestTampering(t *testing.T) {
	f, config := newTaskIssuerFixture(t)
	config.AllowResponses = true
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	r := issuerResponse(f)
	r.Interaction.ExpiresAt = f.now.Add(time.Minute).Format(time.RFC3339)
	if _, err = issuer.issueResponse(r); err == nil {
		t.Fatal("question changed without a new digest")
	}
	refreshIssuerQuestion(&r.Interaction)
	raw, err := issuer.issueResponse(r)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := interactionpermit.Verify(raw, map[string]ed25519.PublicKey{f.keyID: issuer.public}, f.now, config.Validity)
	if err != nil || verified.Statement.ExpiresAt != r.Interaction.ExpiresAt {
		t.Fatalf("expiry cap failed: %v", err)
	}
}
