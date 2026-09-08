package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTaskIssuerFixture(t *testing.T) (*taskCLIFixture, taskIssuerConfig) {
	t.Helper()
	fixture := newTaskCLIFixture(t)
	store := filepath.Join(fixture.directory, "issuer")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	return fixture, taskIssuerConfig{
		Admission: fixture.admissionPath, Intent: fixture.intentPath, Trust: fixture.trustPath,
		Key: fixture.privatePath, KeyID: fixture.keyID, Store: store,
		Operations: []string{fixture.operation.ID}, Validity: 5 * time.Minute, Capacity: 2,
	}
}

func issuerRequest(fixture *taskCLIFixture) taskIssuerRequest {
	return taskIssuerRequest{"issuer-task-1", fixture.operation.ID, base64.StdEncoding.EncodeToString(fixture.request)}
}

func TestTaskIssuerRetainsExactAuthorityAcrossRestartAndExpiry(t *testing.T) {
	fixture, config := newTaskIssuerFixture(t)
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	request := issuerRequest(fixture)
	first, err := issuer.issue(request)
	if err != nil {
		t.Fatal(err)
	}
	if err = issuer.match(first, request, fixture.request); err != nil {
		t.Fatal(err)
	}
	if err = issuer.Close(); err != nil {
		t.Fatal(err)
	}
	issuer, err = openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	replayed, err := issuer.issue(request)
	if err != nil || !bytes.Equal(first, replayed) || issuer.count != 1 {
		t.Fatalf("replay changed authority or count: %v", err)
	}
	previousNow := timeNow
	timeNow = func() time.Time { return fixture.now.Add(10 * time.Minute) }
	defer func() { timeNow = previousNow }()
	if _, err = issuer.issue(request); !errors.Is(err, errTaskIssuerConflict) {
		t.Fatalf("expired task was reissued: %v", err)
	}
}

func TestTaskIssuerRejectsChangedReplayAndUnknownOperation(t *testing.T) {
	fixture, config := newTaskIssuerFixture(t)
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	request := issuerRequest(fixture)
	first, err := issuer.issue(request)
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.RequestBase64 = base64.StdEncoding.EncodeToString([]byte(`{"input":"different"}`))
	if _, err = issuer.issue(changed); !errors.Is(err, errTaskIssuerConflict) {
		t.Fatalf("changed body was accepted: %v", err)
	}
	changed = request
	changed.OperationID = "other"
	if _, err = issuer.issue(changed); err == nil {
		t.Fatal("unapproved operation was signed")
	}
	last, err := issuer.issue(request)
	if err != nil || !bytes.Equal(first, last) {
		t.Fatalf("failed attempts changed original authority: %v", err)
	}
}

func TestTaskIssuerFreezesInputsAndRefusesDifferentConfiguration(t *testing.T) {
	fixture, config := newTaskIssuerFixture(t)
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	if _, err = openTaskIssuer(config); err == nil {
		t.Fatal("second signer opened the same store")
	}
	if err = os.WriteFile(fixture.intentPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = issuer.issue(issuerRequest(fixture)); err != nil {
		t.Fatalf("mutable input replaced the frozen intent: %v", err)
	}
	if err = issuer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = openTaskIssuer(config); err == nil {
		t.Fatal("changed intent reused the authority store")
	}
}

func TestTaskIssuerCapacityAndBusyAreBounded(t *testing.T) {
	fixture, config := newTaskIssuerFixture(t)
	config.Capacity = 1
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	request := issuerRequest(fixture)
	issuer.mu.Lock()
	_, err = issuer.issue(request)
	issuer.mu.Unlock()
	if !errors.Is(err, errTaskIssuerBusy) {
		t.Fatalf("busy signer accepted another request: %v", err)
	}
	if _, err = issuer.issue(request); err != nil {
		t.Fatal(err)
	}
	request.TaskID = "issuer-task-2"
	if _, err = issuer.issue(request); !errors.Is(err, errTaskIssuerCapacity) {
		t.Fatalf("capacity exceeded: %v", err)
	}
	if _, err = issuer.issue(issuerRequest(fixture)); err != nil {
		t.Fatalf("capacity prevented exact recovery: %v", err)
	}
}

func TestTaskIssuerRefusesAmbiguousStoreAndDoesNotRemoveIt(t *testing.T) {
	_, config := newTaskIssuerFixture(t)
	path := filepath.Join(config.Store, "unexpected")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTaskIssuer(config); err == nil {
		t.Fatal("unknown artifact was adopted")
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "keep" {
		t.Fatalf("operator artifact changed: %v", err)
	}
}
