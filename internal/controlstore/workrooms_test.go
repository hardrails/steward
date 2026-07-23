package controlstore

import (
	"errors"
	"testing"
	"time"
)

func TestWorkroomProjectIsBoundedOptimisticAndDurable(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")

	project, changed, err := fixture.store.ApplyWorkroomProject(fixture.admin, WorkroomProject{
		TenantID: "tenant-a", ID: "research", Name: "Research desk",
		Description: "Collect primary sources without exposing tenant authority.",
		AgentRef:    "hermes-research", Skills: []string{"web-research", "analysis", "analysis"},
		Sessions:  []WorkroomSession{{ID: "launch", Title: "Launch research", TaskIDs: []string{}}},
		Artifacts: []WorkroomArtifact{}, MemoryRefs: []WorkroomMemoryReference{},
	}, 0, fixture.now.Add(time.Minute))
	if err != nil || !changed || project.Revision != 1 || len(project.Skills) != 2 || project.Validate() != nil {
		t.Fatalf("create project = (%+v, %v, %v)", project, changed, err)
	}
	replayed, changed, err := fixture.store.ApplyWorkroomProject(fixture.admin, project, project.Revision, fixture.now.Add(2*time.Minute))
	if err != nil || changed || replayed.Revision != project.Revision {
		t.Fatalf("idempotent project apply = (%+v, %v, %v)", replayed, changed, err)
	}

	project.Artifacts = append(project.Artifacts, WorkroomArtifact{
		ID: "report", SessionID: "launch", Name: "Research report", MediaType: "text/markdown",
		Bytes: 512, SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExternalRef: "s3://steward-artifacts/tenant-a/research/report",
	})
	project.MemoryRefs = append(project.MemoryRefs, WorkroomMemoryReference{
		ID: "accepted-report", Title: "Accepted research report", ArtifactID: "report",
	})
	updated, changed, err := fixture.store.ApplyWorkroomProject(
		fixture.admin, project, project.Revision, fixture.now.Add(3*time.Minute),
	)
	if err != nil || !changed || updated.Revision != 2 || updated.Artifacts[0].CreatedAt == "" ||
		updated.MemoryRefs[0].CreatedAt == "" {
		t.Fatalf("update project = (%+v, %v, %v)", updated, changed, err)
	}
	if _, _, err := fixture.store.ApplyWorkroomProject(
		fixture.admin, updated, 1, fixture.now.Add(4*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale project apply error = %v", err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	retained, err := reopened.GetWorkroomProject(fixture.admin, "tenant-a", "research")
	if err != nil || retained.Revision != 2 || len(retained.Artifacts) != 1 || len(retained.MemoryRefs) != 1 {
		t.Fatalf("reopened project = (%+v, %v)", retained, err)
	}
}

func TestWorkroomProjectRejectsDanglingArtifactAndMemoryReferences(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	base := WorkroomProject{
		TenantID: "tenant-a", ID: "research", Name: "Research",
		Sessions:  []WorkroomSession{{ID: "session", Title: "Session", TaskIDs: []string{}}},
		Artifacts: []WorkroomArtifact{}, MemoryRefs: []WorkroomMemoryReference{},
	}
	badArtifact := base
	badArtifact.Artifacts = []WorkroomArtifact{{
		ID: "bad", SessionID: "missing", Name: "Bad", MediaType: "text/plain",
		SHA256:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExternalRef: "s3://bucket/bad",
	}}
	if _, _, err := fixture.store.ApplyWorkroomProject(
		fixture.admin, badArtifact, 0, fixture.now.Add(time.Minute),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("dangling artifact error = %v", err)
	}
	badMemory := base
	badMemory.MemoryRefs = []WorkroomMemoryReference{{ID: "bad", Title: "Bad", ArtifactID: "missing"}}
	if _, _, err := fixture.store.ApplyWorkroomProject(
		fixture.admin, badMemory, 0, fixture.now.Add(time.Minute),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("dangling memory error = %v", err)
	}
}
