package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
)

func scopedInferenceEvent(parent Event) Event {
	event := inferenceEvent()
	event.TenantID, event.RuntimeRef = parent.TenantID, parent.RuntimeRef
	event.CapsuleDigest, event.PolicyDigest = parent.CapsuleDigest, parent.PolicyDigest
	event.RoutePolicyDigest, event.GrantID, event.Generation = parent.RoutePolicyDigest, parent.GrantID, parent.Generation
	event.TaskDigest = "sha256:" + strings.Repeat("9", 64)
	event.InferenceTaskDigest = parent.TaskDigest
	event.InferencePermitDigest, event.InferenceRequestDigest = parent.PermitDigest, parent.RequestDigest
	return event
}

func TestInferenceScopeBindsLiveTaskAcrossRestartAndParentCompletion(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "scope.ndjson")
	log, err := Open(path, private, "node/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	parent := validLifecycleEvent(Authorize, Allowed)
	if _, err := log.Begin(parent); err != nil {
		t.Fatal(err)
	}
	dispatch := validLifecycleDispatch(parent, "scope-run")
	if _, err := log.Dispatch(dispatch); err != nil {
		t.Fatal(err)
	}
	attempt := scopedInferenceEvent(parent)
	if _, err := log.Begin(attempt); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = Open(path, private, "node/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if _, err := log.Finish(validLifecycleTerminal(dispatch, TaskStatusAgentReportedCompleted)); err != nil {
		t.Fatal(err)
	}
	late := attempt
	late.TaskDigest = "sha256:" + strings.Repeat("8", 64)
	if _, err := log.Begin(late); err == nil {
		t.Fatal("completed task authorized another provider attempt")
	}
	terminal := attempt
	terminal.Phase, terminal.Outcome, terminal.HTTPStatus = Terminal, Responded, 200
	changed := terminal
	changed.InferenceRequestDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := log.Finish(changed); err == nil {
		t.Fatal("attempt terminal changed its task scope")
	}
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	var scoped int
	if _, err := VerifyRecords(path, public, "node/gateway", 1, func(record VerifiedReceipt) error {
		if record.Receipt.Event.Kind == InferenceAttempt {
			scoped++
			if record.Receipt.SchemaVersion != SchemaV10 || record.Receipt.Event.InferenceTaskDigest != parent.TaskDigest {
				t.Fatal("task-bound attempt lost its versioned native scope")
			}
			legacy := record.Receipt
			legacy.SchemaVersion = SchemaV9
			if err := validateReceipt(legacy, PayloadTypeV9, legacy.NodeID, legacy.Epoch, legacy.Sequence, legacy.PreviousHash); err == nil {
				t.Fatal("format 9 accepted task-scoped fields")
			}
		}
		return nil
	}); err != nil || scoped != 2 {
		t.Fatalf("scope replay count=%d err=%v", scoped, err)
	}
}

func TestInferenceScopeRejectsUnrelatedOrIncompleteAuthority(t *testing.T) {
	parent := validLifecycleEvent(Authorize, Allowed)
	mutations := map[string]func(*Event){
		"missing-task":    func(e *Event) { e.InferenceTaskDigest = "" },
		"missing-permit":  func(e *Event) { e.InferencePermitDigest = "" },
		"missing-request": func(e *Event) { e.InferenceRequestDigest = "" },
		"task":            func(e *Event) { e.InferenceTaskDigest = "sha256:" + strings.Repeat("a", 64) },
		"permit":          func(e *Event) { e.InferencePermitDigest = "sha256:" + strings.Repeat("b", 64) },
		"request":         func(e *Event) { e.InferenceRequestDigest = "sha256:" + strings.Repeat("c", 64) },
		"tenant":          func(e *Event) { e.TenantID = "other-tenant" },
		"runtime":         func(e *Event) { e.RuntimeRef = "executor-" + strings.Repeat("f", 64) },
		"capsule":         func(e *Event) { e.CapsuleDigest = "sha256:" + strings.Repeat("d", 64) },
		"policy":          func(e *Event) { e.PolicyDigest = "sha256:" + strings.Repeat("e", 64) },
		"route":           func(e *Event) { e.RoutePolicyDigest = "sha256:" + strings.Repeat("f", 64) },
		"grant":           func(e *Event) { e.GrantID = "other-grant" },
		"generation":      func(e *Event) { e.Generation++ },
		"kind":            func(e *Event) { e.Kind = ServiceTask },
		"self":            func(e *Event) { e.TaskDigest = e.InferenceTaskDigest },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			public, private, _ := ed25519.GenerateKey(rand.Reader)
			path := filepath.Join(t.TempDir(), "scope.ndjson")
			log, err := Open(path, private, "node/gateway", 1)
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			if _, err := log.Begin(parent); err != nil {
				t.Fatal(err)
			}
			event := scopedInferenceEvent(parent)
			mutate(&event)
			if _, err := log.Begin(event); err == nil {
				t.Fatal("unrelated or incomplete task scope accepted")
			}
			// A signature alone is insufficient: write a native-signed malformed
			// event below Begin's checks and require the offline reader to refuse.
			log.mu.Lock()
			_, err = log.appendLocked(event, 0)
			log.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRecords(path, public, "node/gateway", 1, nil); err == nil {
				t.Fatal("signature verification accepted an unrelated task scope")
			}
		})
	}
}

func TestInferenceScopeRequiresRootLifecycleAuthority(t *testing.T) {
	parent := validLifecycleEvent(Authorize, Allowed)
	attempt := scopedInferenceEvent(parent)
	for _, variant := range []string{"absent", "connector", "legacy", "control"} {
		t.Run(variant, func(t *testing.T) {
			owner := parent
			switch variant {
			case "connector":
				owner.Kind = ConnectorCall
			case "legacy":
				owner.TaskProtocol = ""
			case "control":
				owner.TargetTaskDigest = "sha256:" + strings.Repeat("a", 64)
			}
			pending := map[string]Event{parent.TaskDigest: owner}
			if variant == "absent" {
				delete(pending, parent.TaskDigest)
			}
			if err := validateInferenceScopeOwner(attempt, pending); err == nil {
				t.Fatal("non-root or absent task authorized inference")
			}
		})
	}
}
