package executor

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/hardrails/steward/internal/admission"
)

func TestRuntimeBoundaryErrorsPreserveTheirUnderlyingCause(t *testing.T) {
	cause := errors.New("backend timed out")
	for name, boundary := range map[string]error{
		"reconcile": &reconcileError{code: "backend_unavailable", err: cause},
		"topology": topologyUnavailable(
			runtimeTopologyGateway,
			"inspect gateway topology",
			cause,
		),
		"start precondition": startPreconditionFailure(cause),
		"failed start":       &runtimeFailedStart{err: cause},
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(boundary, cause) {
				t.Fatalf("boundary error %T did not preserve its cause: %v", boundary, boundary)
			}
			if boundary.Error() == "" {
				t.Fatalf("boundary error %T omitted its operator message", boundary)
			}
		})
	}
	drift := topologyDrift(runtimeTopologyGateway, "gateway policy drift")
	if drift.Error() != "gateway policy drift" || errors.Unwrap(drift) != nil {
		t.Fatalf("durable topology drift = %v, unwrap=%v", drift, errors.Unwrap(drift))
	}
}

func TestEmptyFenceStoreHasNoCommittedLineage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.json")
	if err := admission.InitializeFenceStore(path); err != nil {
		t.Fatal(err)
	}
	fences, err := admission.OpenFenceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{secure: &secureAdmission{fences: fences}}
	if server.lineageHasCommittedFence("tenant-a", "lineage-a") {
		t.Fatal("empty fence store reported a committed lineage")
	}
}
