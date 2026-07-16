package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestPortableTaskEvidenceSurvivesUnrelatedGlobalReceipts(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/gateway.ndjson"
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	authorization := lifecycleTaskEvent(Authorize, Allowed)
	if _, err := log.Begin(authorization); err != nil {
		t.Fatal(err)
	}
	unrelated := validEvent(Deny, Denied)
	unrelated.ErrorCode = "policy_denied"
	if _, err := log.Append(unrelated); err != nil {
		t.Fatal(err)
	}
	dispatch := authorization
	dispatch.Phase, dispatch.Outcome = Dispatch, Responded
	dispatch.HTTPStatus, dispatch.ResponseBytes = 202, 96
	dispatch.RunID = "run_0123456789abcdef0123456789abcdef"
	if _, err := log.Dispatch(dispatch); err != nil {
		t.Fatal(err)
	}
	unrelated.TaskDigest, _ = TaskDigest("unrelated-task")
	if _, err := log.Append(unrelated); err != nil {
		t.Fatal(err)
	}
	terminal := dispatch
	terminal.Phase, terminal.HTTPStatus, terminal.ResponseBytes = Terminal, 200, 512
	terminal.TaskStatus = TaskStatusAgentReportedCompleted
	terminal.ResultDigest = "sha256:" + strings.Repeat("9", 64)
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	var selected []VerifiedReceipt
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		if record.Receipt.Event.TaskDigest == authorization.TaskDigest {
			selected = append(selected, record)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalPortableTaskEvidence(selected)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPortableTaskEvidence(
		raw, public, "node-a/gateway", 1,
		authorization.TaskDigest, authorization.PermitDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Records) != 3 ||
		verified.Records[0].Receipt.Sequence != 1 ||
		verified.Records[1].Receipt.Sequence != 3 ||
		verified.Records[2].Receipt.Sequence != 5 ||
		verified.Terminal.Sequence != 5 ||
		verified.Terminal.ChainHash != selected[2].Hash {
		t.Fatalf("portable task evidence = %#v", verified)
	}
}

func TestPortableTaskEvidenceAcceptsAuthorizedTerminalFailure(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/gateway.ndjson"
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	authorization := lifecycleTaskEvent(Authorize, Allowed)
	if _, err := log.Begin(authorization); err != nil {
		t.Fatal(err)
	}
	terminal := authorization
	terminal.Phase, terminal.Outcome = Terminal, Failed
	terminal.ErrorCode = "upstream_unavailable"
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var selected []VerifiedReceipt
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		selected = append(selected, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalPortableTaskEvidence(selected)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPortableTaskEvidence(
		raw, public, "node-a/gateway", 1,
		authorization.TaskDigest, authorization.PermitDigest,
	)
	if err != nil || len(verified.Records) != 2 {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
}

func TestPortableTaskEvidenceRejectsTamperingAndAmbiguity(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/gateway.ndjson"
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	authorization := lifecycleTaskEvent(Authorize, Allowed)
	if _, err := log.Begin(authorization); err != nil {
		t.Fatal(err)
	}
	terminal := authorization
	terminal.Phase, terminal.Outcome, terminal.ErrorCode = Terminal, Failed, "upstream_unavailable"
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var selected []VerifiedReceipt
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		selected = append(selected, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalPortableTaskEvidence(selected)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][]byte{
		"missing final newline": raw[:len(raw)-1],
		"changed signature":     append(append([]byte(nil), raw[:20]...), append([]byte{'x'}, raw[21:]...)...),
		"blank line":            append(append([]byte(nil), raw...), '\n'),
		"reordered": append(
			append([]byte(nil), selected[1].Raw...),
			append([]byte{'\n'}, append(selected[0].Raw, '\n')...)...,
		),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyPortableTaskEvidence(
				candidate, public, "node-a/gateway", 1,
				authorization.TaskDigest, authorization.PermitDigest,
			); err == nil {
				t.Fatal("invalid portable task evidence accepted")
			}
		})
	}
	if _, err := VerifyPortableTaskEvidence(
		raw, public, "node-a/gateway", 1,
		"sha256:"+strings.Repeat("8", 64), authorization.PermitDigest,
	); err == nil {
		t.Fatal("substituted task digest accepted")
	}
}

func lifecycleTaskEvent(phase Phase, outcome Outcome) Event {
	event := validServiceTaskEvent(phase, outcome)
	event.ServiceID = "hermes-api"
	event.OperationID = "hermes.run"
	event.TaskProtocol = TaskProtocolLifecycleV1
	return event
}
