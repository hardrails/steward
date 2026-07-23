package controlstore

import (
	"errors"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
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
	updated.Sessions[0].Title = "Launch verified research"
	updated, changed, err = fixture.store.ApplyWorkroomProject(
		fixture.admin, updated, updated.Revision, fixture.now.Add(4*time.Minute),
	)
	if err != nil || !changed || updated.Revision != 3 {
		t.Fatalf("session update = (%+v, %v, %v)", updated, changed, err)
	}
	updated.Artifacts[0].Name = "Verified research report"
	updated, changed, err = fixture.store.ApplyWorkroomProject(
		fixture.admin, updated, updated.Revision, fixture.now.Add(5*time.Minute),
	)
	if err != nil || !changed || updated.Revision != 4 {
		t.Fatalf("artifact update = (%+v, %v, %v)", updated, changed, err)
	}
	updated.MemoryRefs[0].Title = "Accepted verified report"
	updated, changed, err = fixture.store.ApplyWorkroomProject(
		fixture.admin, updated, updated.Revision, fixture.now.Add(6*time.Minute),
	)
	if err != nil || !changed || updated.Revision != 5 {
		t.Fatalf("memory update = (%+v, %v, %v)", updated, changed, err)
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
	if err != nil || retained.Revision != 5 || len(retained.Artifacts) != 1 || len(retained.MemoryRefs) != 1 ||
		retained.Sessions[0].Title != "Launch verified research" ||
		retained.Artifacts[0].Name != "Verified research report" ||
		retained.MemoryRefs[0].Title != "Accepted verified report" {
		t.Fatalf("reopened project = (%+v, %v)", retained, err)
	}
}

func TestNilWorkroomStoreFailsClosed(t *testing.T) {
	var store *Store
	actor := controlauth.Identity{Role: controlauth.RoleSiteAdmin}
	if _, _, err := store.ApplyWorkroomProject(actor, WorkroomProject{}, 0, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil apply error = %v", err)
	}
	if _, err := store.ListWorkroomProjects(actor, "tenant-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil list error = %v", err)
	}
	if _, err := store.GetWorkroomProject(actor, "tenant-a", "project-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil get error = %v", err)
	}
	if err := store.DeleteWorkroomProject(actor, "tenant-a", "project-a", 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil delete error = %v", err)
	}
}

func TestWorkroomValidationRejectsAmbiguousNestedReferences(t *testing.T) {
	now := canonicalTimestamp(time.Now())
	base := WorkroomProject{
		TenantID: "tenant-a", ID: "research", Name: "Research", Revision: 1,
		CreatedAt: now, UpdatedAt: now, Skills: []string{"analysis"},
		Sessions: []WorkroomSession{{
			ID: "session-a", Title: "Session A", State: "active",
			TaskIDs: []string{"task-a"}, CreatedAt: now, UpdatedAt: now,
		}},
		Artifacts: []WorkroomArtifact{{
			ID: "artifact-a", SessionID: "session-a", TaskID: "task-a",
			Name: "Report", MediaType: "text/markdown",
			SHA256:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ExternalRef: "s3://bucket/report", CreatedAt: now,
		}},
		MemoryRefs: []WorkroomMemoryReference{{
			ID: "memory-a", Title: "Accepted report", ArtifactID: "artifact-a", CreatedAt: now,
		}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid workroom = %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*WorkroomProject)
	}{
		{"invalid skill", func(project *WorkroomProject) { project.Skills[0] = "bad skill" }},
		{"duplicate session", func(project *WorkroomProject) {
			project.Sessions = append(project.Sessions, project.Sessions[0])
		}},
		{"invalid task", func(project *WorkroomProject) { project.Sessions[0].TaskIDs[0] = "bad task" }},
		{"duplicate task", func(project *WorkroomProject) {
			project.Sessions = append(project.Sessions, WorkroomSession{
				ID: "session-b", Title: "Session B", State: "active",
				TaskIDs: []string{"task-a"}, CreatedAt: now, UpdatedAt: now,
			})
		}},
		{"missing artifact session", func(project *WorkroomProject) {
			project.Artifacts[0].SessionID = "missing"
		}},
		{"missing artifact task", func(project *WorkroomProject) {
			project.Artifacts[0].TaskID = "missing"
		}},
		{"duplicate artifact", func(project *WorkroomProject) {
			project.Artifacts = append(project.Artifacts, project.Artifacts[0])
		}},
		{"invalid memory", func(project *WorkroomProject) { project.MemoryRefs[0].Title = "" }},
		{"missing memory artifact", func(project *WorkroomProject) {
			project.MemoryRefs[0].ArtifactID = "missing"
		}},
		{"duplicate memory", func(project *WorkroomProject) {
			project.MemoryRefs = append(project.MemoryRefs, project.MemoryRefs[0])
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			project := cloneWorkroomProject(base)
			test.mutate(&project)
			if err := project.Validate(); err == nil {
				t.Fatal("invalid workroom accepted")
			}
		})
	}
}

func TestWorkroomProjectDeletionIsRevisionGuarded(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	project := WorkroomProject{TenantID: "tenant-a", ID: "temporary", Name: "Temporary"}
	if _, _, err := fixture.store.ApplyWorkroomProject(fixture.admin, project, 0, time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zero-time apply error = %v", err)
	}
	if _, _, err := fixture.store.ApplyWorkroomProject(fixture.admin, project, 1, fixture.now); !errors.Is(err, ErrConflict) {
		t.Fatalf("new project stale revision error = %v", err)
	}
	retained, changed, err := fixture.store.ApplyWorkroomProject(fixture.admin, project, 0, fixture.now)
	if err != nil || !changed {
		t.Fatalf("create temporary project = (%+v, %v, %v)", retained, changed, err)
	}
	if err := fixture.store.DeleteWorkroomProject(
		fixture.admin, "tenant-a", "temporary", retained.Revision+1,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete error = %v", err)
	}
	if err := fixture.store.DeleteWorkroomProject(
		fixture.admin, "tenant-a", "temporary", retained.Revision,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.GetWorkroomProject(
		fixture.admin, "tenant-a", "temporary",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted project get error = %v", err)
	}
	if err := fixture.store.DeleteWorkroomProject(
		fixture.admin, "tenant-a", "temporary", retained.Revision,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeated delete error = %v", err)
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
