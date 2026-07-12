package uplink

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hardrails/steward/internal/runtime"
)

type destroyFailureTracker struct {
	*runtime.Tracker
	destroyErr error
}

func (t *destroyFailureTracker) Destroy(string) (*runtime.Instance, error) {
	return nil, t.destroyErr
}

func TestDestroyDistinguishesConcurrentAbsenceFromRuntimeFailure(t *testing.T) {
	for name, destroyErr := range map[string]error{
		"concurrent absence": runtime.ErrNotFound,
		"runtime failure":    errors.New("runtime unavailable"),
	} {
		t.Run(name, func(t *testing.T) {
			tracker := runtime.NewTracker(0)
			if _, _, err := tracker.Provision("agent-1", 1, nil); err != nil {
				t.Fatal(err)
			}
			d := dispatcher{
				tracker: &destroyFailureTracker{Tracker: tracker, destroyErr: destroyErr},
				nodeID:  "node-7", logger: discardLogger(), metrics: &Metrics{},
			}
			report, retry, fenced := d.execute(cmd("destroy", "node-7", "agent-1", kindDestroy, "", 1))
			if retry || fenced {
				t.Fatalf("retry=%v fenced=%v", retry, fenced)
			}
			if errors.Is(destroyErr, runtime.ErrNotFound) {
				if report.Status != statusDone || report.ReportedStatus != "stopped" {
					t.Fatalf("concurrent absence report = %#v", report)
				}
			} else if report.Status != statusFailed || report.ReportedStatus != "failed" {
				t.Fatalf("runtime failure report = %#v", report)
			}
		})
	}
}

func TestUnmappableRuntimeStatusFailsClosed(t *testing.T) {
	d := dispatcher{logger: discardLogger(), metrics: &Metrics{}}
	if _, ok := reportedStatus(runtime.Status("UNKNOWN")); ok {
		t.Fatal("unknown runtime status mapped to the wire")
	}
	report := d.succeed(report{CommandID: "c"}, runtime.Status("UNKNOWN"))
	if report.Status != statusFailed || report.ReportedStatus != "failed" {
		t.Fatalf("report = %#v", report)
	}
	if detail := auditErrorDetail(json.RawMessage(`not-json`)); detail != "" {
		t.Fatalf("malformed audit detail = %q", detail)
	}
}
