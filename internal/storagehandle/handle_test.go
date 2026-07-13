package storagehandle

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestReferenceStrictCanonicalContract(t *testing.T) {
	want := Reference{Version: Version, HandleID: "sh_01", Generation: 7, Kind: KindState}
	encoded, err := MarshalReference(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(encoded); got != `{"version":1,"handle_id":"sh_01","generation":7,"kind":"state"}` {
		t.Fatalf("canonical JSON = %s", got)
	}
	got, err := ParseReference(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != want {
		t.Fatalf("reference = %#v, want %#v", got, want)
	}
}

func TestReferenceRejectsAmbiguousOrPrivilegedInputs(t *testing.T) {
	tests := map[string]string{
		"unknown path":    `{"version":1,"handle_id":"sh_01","generation":1,"kind":"state","path":"/tmp/x"}`,
		"unknown uid":     `{"version":1,"handle_id":"sh_01","generation":1,"kind":"state","uid":0}`,
		"duplicate":       `{"version":1,"handle_id":"sh_01","handle_id":"sh_02","generation":1,"kind":"state"}`,
		"unsupported":     `{"version":2,"handle_id":"sh_01","generation":1,"kind":"state"}`,
		"path identifier": `{"version":1,"handle_id":"../state","generation":1,"kind":"state"}`,
		"zero generation": `{"version":1,"handle_id":"sh_01","generation":0,"kind":"state"}`,
		"trailing value":  `{"version":1,"handle_id":"sh_01","generation":1,"kind":"state"} {}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReference(strings.NewReader(input)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestReferenceBodyIsBounded(t *testing.T) {
	input := strings.Repeat(" ", maxReferenceBytes+1)
	if _, err := ParseReference(strings.NewReader(input)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestRegistryBindsScopeAndDerivesPath(t *testing.T) {
	registry, err := NewRegistry("/srv/steward-preprovisioned", 2)
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	record := testRecord()
	created, err := registry.Add(record)
	if err != nil || !created {
		t.Fatalf("add: created=%v err=%v", created, err)
	}
	created, err = registry.Add(record)
	if err != nil || created {
		t.Fatalf("idempotent add: created=%v err=%v", created, err)
	}

	resolved, err := registry.Resolve(record.Reference, testScope())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Path != "/srv/steward-preprovisioned/state/backend_01" {
		t.Fatalf("path = %q", resolved.Path)
	}
	if strings.Contains(string(mustMarshal(t, record.Reference)), resolved.Path) {
		t.Fatal("wire reference exposed resolved path")
	}
	encodedRecord, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	for _, private := range []string{"tenant_a", "lineage_a", "backend_01", resolved.Path, "ready"} {
		if strings.Contains(string(encodedRecord), private) {
			t.Fatalf("marshaled record exposed private value %q: %s", private, encodedRecord)
		}
	}

	wrongScope := testScope()
	wrongScope.TenantID = "tenant_b"
	if _, err := registry.Resolve(record.Reference, wrongScope); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("wrong-scope error = %v", err)
	}
}

func TestRegistryRejectsRebindingAndCapacityOverflow(t *testing.T) {
	registry, err := NewRegistry("/srv/steward-preprovisioned", 1)
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	record := testRecord()
	if _, err := registry.Add(record); err != nil {
		t.Fatalf("add: %v", err)
	}
	rebound := record
	rebound.BackendID = "backend_02"
	if _, err := registry.Add(rebound); !errors.Is(err, ErrConflict) {
		t.Fatalf("rebind error = %v", err)
	}
	second := record
	second.HandleID = "sh_02"
	if _, err := registry.Add(second); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
}

func TestRegistryRevocationCannotResurrect(t *testing.T) {
	registry, err := NewRegistry("/srv/steward-preprovisioned", 1)
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	record := testRecord()
	if _, err := registry.Add(record); err != nil {
		t.Fatalf("add: %v", err)
	}
	changed, err := registry.Revoke(record.Reference, testScope())
	if err != nil || !changed {
		t.Fatalf("revoke: changed=%v err=%v", changed, err)
	}
	changed, err = registry.Revoke(record.Reference, testScope())
	if err != nil || changed {
		t.Fatalf("idempotent revoke: changed=%v err=%v", changed, err)
	}
	if _, err := registry.Resolve(record.Reference, testScope()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("resolve revoked error = %v", err)
	}
	record.Status = StatusReady
	if _, err := registry.Add(record); !errors.Is(err, ErrConflict) {
		t.Fatalf("resurrection error = %v", err)
	}
}

func TestConcurrentAddCreatesOneBinding(t *testing.T) {
	registry, err := NewRegistry("/srv/steward-preprovisioned", 1)
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	record := testRecord()
	var wait sync.WaitGroup
	var created int
	var mu sync.Mutex
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			wasCreated, addErr := registry.Add(record)
			if addErr != nil {
				t.Errorf("add: %v", addErr)
				return
			}
			if wasCreated {
				mu.Lock()
				created++
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	if created != 1 {
		t.Fatalf("created count = %d, want 1", created)
	}
}

func TestRegistryRejectsUnsafeRootAndRecord(t *testing.T) {
	for _, root := range []string{"", "/", "relative", "/srv/../tmp"} {
		if _, err := NewRegistry(root, 1); !errors.Is(err, ErrInvalid) {
			t.Fatalf("root %q error = %v", root, err)
		}
	}
	registry, err := NewRegistry("/srv/steward-preprovisioned", 1)
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	record := testRecord()
	record.BackendID = "../escape"
	if _, err := registry.Add(record); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe backend error = %v", err)
	}
}

func testRecord() Record {
	return Record{
		Reference: Reference{Version: Version, HandleID: "sh_01", Generation: 1, Kind: KindState},
		TenantID:  "tenant_a", LineageID: "lineage_a", BackendID: "backend_01", Status: StatusReady,
	}
}

func testScope() Scope {
	return Scope{TenantID: "tenant_a", LineageID: "lineage_a", Kind: KindState}
}

func mustMarshal(t *testing.T, reference Reference) []byte {
	t.Helper()
	encoded, err := MarshalReference(reference)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}
