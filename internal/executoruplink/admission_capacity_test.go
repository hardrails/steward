package executoruplink

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestAdmissionCapacityRejectionIsNarrowAndComplete(t *testing.T) {
	const capacity = `{"error":"capacity_exceeded","message":"host CPU capacity is exhausted"}`
	for _, test := range []struct {
		name      string
		status    int
		body      string
		uncertain bool
	}{
		{"capacity", 503, capacity, false},
		{"different status", 500, capacity, true},
		{"different code", 503, `{"error":"reconciliation_required","message":"blocked"}`, true},
		{"state capacity", 507, `{"error":"state_capacity_exceeded","message":"full"}`, true},
		{"missing message", 503, `{"error":"capacity_exceeded"}`, true},
		{"empty message", 503, `{"error":"capacity_exceeded","message":" "}`, true},
		{"extra field", 503, `{"error":"capacity_exceeded","message":"full","accepted":true}`, true},
		{"duplicate field", 503, `{"error":"capacity_exceeded","error":"capacity_exceeded","message":"full"}`, true},
		{"trailing value", 503, capacity + `{}`, true},
		{"truncated", 503, capacity[:len(capacity)-1], true},
		{"oversized", 503, capacity + strings.Repeat(" ", 1<<20), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := dispatcher{token: "token", handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/admissions" {
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			})}
			for attempt := 0; attempt < 2; attempt++ {
				_, v3err := d.call(context.Background(), http.MethodPost, "/v1/admissions", admissionPayload{})
				_, projection, v4err := d.callAdmissionV4(context.Background(), admissionPayload{}, "unused")
				if projection != nil {
					t.Fatal("failed admission returned a projection")
				}
				for _, err := range []error{v3err, v4err} {
					if err == nil || effectMayHaveOccurred(err) != test.uncertain {
						t.Fatalf("attempt %d: uncertain=%t, err=%v", attempt, test.uncertain, err)
					}
					local := report{Status: controlprotocol.ExecutorStatusFailed, ReportedStatus: "failed", ClaimGeneration: 1,
						Result: map[string]any{"error": err.Error()}, effectUncertain: effectMayHaveOccurred(err)}
					v3 := makeReportV3(deliveryFixture("capacity", 1), local)
					v4 := makeReportV4(deliveryFixtureV4("capacity", 1), local, "admit")
					want := controlprotocol.ExecutorStatusRejected
					if test.uncertain {
						want = controlprotocol.ExecutorStatusOutcomeUnknown
					}
					if v3.Status != want || v4.Status != want || v4.Result.Admission != nil {
						t.Fatalf("v3=%#v v4=%#v", v3, v4)
					}
				}
			}
		})
	}
}

func TestCapacityRefusalDoesNotAdvanceDeliveryFence(t *testing.T) {
	for _, projectAdmission := range []bool{false, true} {
		calls := 0
		statePath := filepath.Join(t.TempDir(), "state.json")
		d := dispatcher{
			token: "token", tenantID: "tenant-a", nodeID: "node-1", projectAdmission: projectAdmission,
			state: newStateStore(t, statePath),
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/v1/admissions" {
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"capacity_exceeded","message":"host CPU capacity is exhausted"}`))
			}),
		}
		payload, err := json.Marshal(admissionPayload{CapsuleDSSEBase64: "opaque", Intent: admission.InstanceIntent{
			TenantID: "tenant-a", NodeID: "node-1", InstanceID: "agent-1", Generation: 1,
		}})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := RuntimeRefV2("tenant-a", "node-1", "agent-1")
		if err != nil {
			t.Fatal(err)
		}
		cmd := command{CommandID: "capacity", TenantID: "tenant-a", NodeID: "node-1", InstanceID: "agent-1",
			RuntimeRef: ref, Kind: "admit", Payload: payload, signed: true,
			ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1}
		for attempt := 1; attempt <= 2; attempt++ {
			local := d.execute(context.Background(), cmd)
			if calls != attempt || local.Status != controlprotocol.ExecutorStatusFailed || local.effectUncertain || local.admission != nil {
				t.Fatalf("projection=%t attempt=%d calls=%d report=%#v", projectAdmission, attempt, calls, local)
			}
			if _, exists := d.state.position("tenant-a", "agent-1"); exists {
				t.Fatal("capacity refusal advanced the delivery fence")
			}
			d.state, err = LoadStateStore(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := d.state.position("tenant-a", "agent-1"); exists {
				t.Fatal("capacity refusal persisted a delivery fence")
			}
		}
	}
}

func TestCapacityResponseDoesNotClassifyOtherMutationsAsRejected(t *testing.T) {
	d := dispatcher{handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"capacity_exceeded","message":"full"}`))
	})}
	for _, call := range []struct{ method, path string }{
		{http.MethodPost, "/v1/workloads"},
		{http.MethodPost, "/v1/workloads/ref/start"},
		{http.MethodDelete, "/v1/admissions"},
	} {
		_, err := d.call(context.Background(), call.method, call.path, nil)
		if err == nil || !effectMayHaveOccurred(err) {
			t.Fatalf("%s %s: %v", call.method, call.path, err)
		}
	}
}
