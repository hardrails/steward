package executoruplink

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
)

func TestDispatcherRejectsMissingFencesAndUnsignedNodeCommands(t *testing.T) {
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	d := dispatcher{
		handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("rejected command reached local Executor")
		}),
		token: "local", tenantID: "tenant-a", nodeID: "node-1", state: store,
	}
	validRef := "uplink:6:node-1:agent-1"
	for name, command := range map[string]command{
		"missing command ID": {
			TenantID: "tenant-a", NodeID: "node-1", RuntimeRef: validRef, Kind: "start",
			ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
		},
		"missing claim generation": {
			CommandID: "c", TenantID: "tenant-a", NodeID: "node-1", RuntimeRef: validRef, Kind: "start",
			InstanceGeneration: 1, CommandSequence: 1,
		},
		"unsigned node scoped": {
			CommandID: "c", TenantID: "tenant-a", NodeID: "node-1", InstanceID: "agent-1",
			RuntimeRef: "uplink:v2:8:tenant-a:6:node-1:agent-1", Kind: "read",
			ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := d
			if name == "unsigned node scoped" {
				candidate.nodeScoped = true
			}
			if report := candidate.execute(context.Background(), command); report.Status != "failed" {
				t.Fatalf("report = %#v", report)
			}
		})
	}
}

func TestDispatcherReportsFencePersistenceFailure(t *testing.T) {
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	store.path = t.TempDir() // force the atomic rename to fail after the local response.
	localCalls := 0
	d := dispatcher{
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			localCalls++
			_, _ = w.Write([]byte(`{"status":"running"}`))
		}),
		token: "local", tenantID: "tenant-a", nodeID: "node-1", state: store,
	}
	report := d.execute(context.Background(), command{
		CommandID: "start-1", TenantID: "tenant-a", NodeID: "node-1",
		RuntimeRef: "uplink:6:node-1:agent-1", Kind: "start",
		ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
	})
	if report.Status != "failed" || !strings.Contains(report.Result["error"].(string), "persist command fence") {
		t.Fatalf("report = %#v", report)
	}
	if localCalls != 1 {
		t.Fatalf("local calls = %d", localCalls)
	}
	if _, ok := store.position("tenant-a", "agent-1"); ok {
		t.Fatal("failed fence persistence was published in memory")
	}
}

func TestApplyRejectsMalformedOrProtocolIncompatiblePayloads(t *testing.T) {
	localCalls := 0
	d := dispatcher{
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			localCalls++
			http.Error(w, "local rejection", http.StatusConflict)
		}),
		token: "local", nodeID: "node-1",
	}
	base := command{signed: true, InstanceGeneration: 2}
	for name, candidate := range map[string]command{
		"malformed admission": {Kind: "admit", Payload: json.RawMessage(`{`), signed: true, InstanceGeneration: 2},
		"signed provision":    {Kind: "provision", Payload: json.RawMessage(`{}`), signed: true, InstanceGeneration: 2},
		"malformed start":     {Kind: "start", Payload: json.RawMessage(`{"unexpected":true}`), signed: true, InstanceGeneration: 2},
		"malformed stop":      {Kind: "stop", Payload: json.RawMessage(`[]`), signed: true, InstanceGeneration: 2},
		"malformed destroy":   {Kind: "destroy", Payload: json.RawMessage(`null`), signed: true, InstanceGeneration: 2},
		"malformed read":      {Kind: "read", Payload: json.RawMessage(`{"unexpected":true}`), signed: true, InstanceGeneration: 2},
		"malformed purge":     {Kind: "purge", Payload: json.RawMessage(`{"lineage_id":""}`), signed: true, InstanceGeneration: 2},
		"malformed snapshot":  {Kind: "snapshot-state", Payload: json.RawMessage(`{"lineage_id":"lineage-a","snapshot_id":""}`), signed: true, InstanceGeneration: 2},
		"malformed clone":     {Kind: "clone-state", Payload: json.RawMessage(`{"lineage_id":"same","snapshot_id":"snapshot-a","source_lineage_id":"same"}`), signed: true, InstanceGeneration: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := d.apply(context.Background(), candidate, "tenant-a", "agent-1", "executor-ref"); err == nil {
				t.Fatal("invalid payload was accepted")
			}
		})
	}
	if localCalls != 0 {
		t.Fatalf("invalid payloads reached local Executor %d times", localCalls)
	}

	base.Kind, base.Payload = "destroy", json.RawMessage(`{}`)
	if _, err := d.apply(context.Background(), base, "tenant-a", "agent-1", "executor-ref"); err == nil {
		t.Fatal("destroy hid local Executor rejection")
	}
	base.Kind, base.Payload = "purge", json.RawMessage(`{"lineage_id":"lineage-a"}`)
	if _, err := d.apply(context.Background(), base, "tenant-a", "agent-1", "executor-ref"); err == nil {
		t.Fatal("purge hid local Executor rejection")
	}
}

func TestLegacyProvisionRequiresExactlyOneJSONValue(t *testing.T) {
	d := dispatcher{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("malformed provision reached local Executor")
	})}
	for name, payload := range map[string]json.RawMessage{
		"second value":       json.RawMessage(`{} {}`),
		"malformed trailing": json.RawMessage(`{} x`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := d.apply(context.Background(), command{Kind: "provision", Payload: payload}, "tenant-a", "agent", "ref")
			if err == nil || !strings.Contains(err.Error(), "invalid provision payload") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestLocalCallPropagatesTransportAndResponseErrors(t *testing.T) {
	d := dispatcher{token: "local"}
	if _, err := d.call(context.Background(), http.MethodPost, "/v1/workloads", func() {}); err == nil {
		t.Fatal("unencodable local request body was accepted")
	}
	if _, err := d.call(context.Background(), "bad\nmethod", "/v1/workloads", nil); err == nil {
		t.Fatal("invalid HTTP method was accepted")
	}

	for name, handler := range map[string]http.Handler{
		"HTTP error": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "denied", http.StatusForbidden)
		}),
		"malformed success": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}),
		"unsupported status": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"mystery"}`))
		}),
	} {
		t.Run(name, func(t *testing.T) {
			d.handler = handler
			if _, err := d.call(context.Background(), http.MethodGet, "/v1/workloads/ref", nil); err == nil {
				t.Fatal("invalid local response was accepted")
			}
		})
	}
	d.handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	if status, err := d.call(context.Background(), http.MethodDelete, "/v1/workloads/ref", nil); err != nil || status != "stopped" {
		t.Fatalf("204 response = %q, %v", status, err)
	}
}

func TestRuntimeReferencesRejectAmbiguousBoundaries(t *testing.T) {
	for name, identity := range map[string][3]string{
		"empty tenant":      {"", "node", "agent"},
		"oversized node":    {"tenant", strings.Repeat("n", 129), "agent"},
		"nul instance":      {"tenant", "node", "agent\x00one"},
		"invalid utf8 node": {"tenant", string([]byte{0xff}), "agent"},
	} {
		t.Run("construct "+name, func(t *testing.T) {
			if ref, err := RuntimeRefV2(identity[0], identity[1], identity[2]); err == nil || ref != "" {
				t.Fatalf("RuntimeRefV2 = %q, %v", ref, err)
			}
		})
	}

	for name, ref := range map[string]string{
		"v2 missing tenant length": "uplink:v2:tenant",
		"v2 invalid tenant length": "uplink:v2:x:tenant:4:node:agent",
		"v2 noncanonical length":   "uplink:v2:06:tenant:4:node:agent",
		"v2 tenant overrun":        "uplink:v2:99:tenant:4:node:agent",
		"v2 missing node length":   "uplink:v2:6:tenant:node",
		"v2 invalid identity":      "uplink:v2:1: :4:node:agent",
		"v1 missing prefix":        "runtime:4:node:agent",
		"v1 missing node length":   "uplink::node:agent",
		"v1 invalid node length":   "uplink:x:node:agent",
		"v1 node length overrun":   "uplink:99:node:agent",
		"v1 invalid utf8 node":     "uplink:1:\xff:agent",
		"v1 missing separator":     "uplink:4:node-agent",
		"v1 empty instance":        "uplink:4:node:",
	} {
		t.Run("parse "+name, func(t *testing.T) {
			if identity, err := parseRuntimeRef(ref); err == nil || identity != (runtimeIdentity{}) {
				t.Fatalf("parseRuntimeRef = %#v, %v", identity, err)
			}
		})
	}
}

func TestAdmissionPayloadIdentityMustMatchCommand(t *testing.T) {
	d := dispatcher{nodeID: "node-1", handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("mismatched admission reached local Executor")
	})}
	payload, err := json.Marshal(admissionPayload{
		CapsuleDSSEBase64: "opaque",
		Intent: admission.InstanceIntent{
			TenantID: "tenant-a", NodeID: "node-1", InstanceID: "another-agent", Generation: 2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.apply(context.Background(), command{
		Kind: "admit", Payload: payload, signed: true, InstanceGeneration: 2,
	}, "tenant-a", "agent-1", "ref"); err == nil {
		t.Fatal("mismatched admission identity was accepted")
	}
}
