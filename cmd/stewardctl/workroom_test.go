package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestWorkroomCommandsCompleteProjectLifecycle(t *testing.T) {
	const timestamp = "2026-07-23T09:00:00Z"
	var mu sync.Mutex
	var project *controlstore.WorkroomProject
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer admin-secret" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case request.URL.Path == "/v1/tenants/tenant-a/projects" && request.Method == http.MethodGet:
			if request.URL.Query().Get("after") != "" || request.URL.Query().Get("limit") != "25" {
				t.Fatalf("list query = %q", request.URL.RawQuery)
			}
			page := controlclient.WorkroomProjectList{Projects: []controlstore.WorkroomProject{}}
			if project != nil {
				page.Projects = append(page.Projects, *project)
				page.NextAfter = project.ID
			}
			if err := json.NewEncoder(writer).Encode(page); err != nil {
				t.Fatal(err)
			}
		case request.URL.Path == "/v1/tenants/tenant-a/projects/research" && request.Method == http.MethodGet:
			if project == nil {
				http.Error(writer, `{"error":"not_found","message":"missing"}`, http.StatusNotFound)
				return
			}
			if err := json.NewEncoder(writer).Encode(project); err != nil {
				t.Fatal(err)
			}
		case request.URL.Path == "/v1/tenants/tenant-a/projects/research" && request.Method == http.MethodPut:
			var input struct {
				ExpectedRevision uint64                                 `json:"expected_revision"`
				Name             string                                 `json:"name"`
				Description      string                                 `json:"description"`
				AgentRef         string                                 `json:"agent_ref"`
				Skills           []string                               `json:"skills"`
				Sessions         []controlstore.WorkroomSession         `json:"sessions"`
				Artifacts        []controlstore.WorkroomArtifact        `json:"artifacts"`
				MemoryRefs       []controlstore.WorkroomMemoryReference `json:"memory_refs"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			currentRevision := uint64(0)
			createdAt := timestamp
			if project != nil {
				currentRevision = project.Revision
				createdAt = project.CreatedAt
			}
			if input.ExpectedRevision != currentRevision {
				t.Fatalf("expected revision = %d, current = %d", input.ExpectedRevision, currentRevision)
			}
			for index := range input.Sessions {
				if input.Sessions[index].State == "" {
					input.Sessions[index].State = "active"
				}
				if input.Sessions[index].CreatedAt == "" {
					input.Sessions[index].CreatedAt = timestamp
				}
				if input.Sessions[index].UpdatedAt == "" {
					input.Sessions[index].UpdatedAt = timestamp
				}
			}
			for index := range input.Artifacts {
				if input.Artifacts[index].CreatedAt == "" {
					input.Artifacts[index].CreatedAt = timestamp
				}
			}
			for index := range input.MemoryRefs {
				if input.MemoryRefs[index].CreatedAt == "" {
					input.MemoryRefs[index].CreatedAt = timestamp
				}
			}
			project = &controlstore.WorkroomProject{
				TenantID: "tenant-a", ID: "research", Name: input.Name,
				Description: input.Description, AgentRef: input.AgentRef, Skills: input.Skills,
				Sessions: input.Sessions, Artifacts: input.Artifacts, MemoryRefs: input.MemoryRefs,
				Revision: currentRevision + 1, CreatedAt: createdAt, UpdatedAt: timestamp,
			}
			if err := project.Validate(); err != nil {
				t.Fatalf("project response is invalid: %+v: %v", project, err)
			}
			if err := json.NewEncoder(writer).Encode(project); err != nil {
				t.Fatal(err)
			}
		case request.URL.Path == "/v1/tenants/tenant-a/projects/research" && request.Method == http.MethodDelete:
			var input struct {
				ExpectedRevision uint64 `json:"expected_revision"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if project == nil || input.ExpectedRevision != project.Revision {
				t.Fatalf("delete revision = %d project = %+v", input.ExpectedRevision, project)
			}
			project = nil
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
	}))
	defer server.Close()

	tokenPath := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenPath, []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"-control-url", server.URL, "-token-file", tokenPath, "-tenant-id", "tenant-a"}
	runWorkroom := func(arguments ...string) string {
		t.Helper()
		var output bytes.Buffer
		if err := run(append([]string{"workroom"}, arguments...), &output, &bytes.Buffer{}); err != nil {
			t.Fatalf("workroom %v: %v", arguments, err)
		}
		return output.String()
	}

	output := runWorkroom(append([]string{"create", "research"}, append(common,
		"-name", "Research desk", "-description", "Primary sources", "-agent", "hermes-research")...)...)
	if !strings.Contains(output, `"revision":1`) || !strings.Contains(output, `"name":"Research desk"`) {
		t.Fatalf("create output = %q", output)
	}
	output = runWorkroom(append([]string{"list"}, append(common, "-limit", "25")...)...)
	if !strings.Contains(output, `"next_after":"research"`) {
		t.Fatalf("list output = %q", output)
	}
	output = runWorkroom(append([]string{"show", "research"}, common...)...)
	if !strings.Contains(output, `"id":"research"`) {
		t.Fatalf("show output = %q", output)
	}
	output = runWorkroom(append([]string{"session", "create", "research"}, append(common,
		"-id", "sources", "-title", "Source review")...)...)
	if !strings.Contains(output, `"id":"sources"`) || !strings.Contains(output, `"revision":2`) {
		t.Fatalf("session output = %q", output)
	}
	var duplicateOutput bytes.Buffer
	duplicateArguments := append([]string{"workroom", "session", "create", "research"}, append(common,
		"-id", "sources", "-title", "Duplicate")...)
	if err := run(duplicateArguments, &duplicateOutput, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate session output=%q error=%v", duplicateOutput.String(), err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	output = runWorkroom(append([]string{"artifact", "add", "research"}, append(common,
		"-session", "sources", "-id", "report", "-name", "Report", "-media-type", "text/markdown",
		"-bytes", "42", "-sha256", digest, "-ref", "objects/research/report")...)...)
	if !strings.Contains(output, `"id":"report"`) || !strings.Contains(output, `"revision":3`) {
		t.Fatalf("artifact output = %q", output)
	}
	output = runWorkroom(append([]string{"memory", "add", "research"}, append(common,
		"-id", "accepted-report", "-title", "Accepted report", "-artifact", "report")...)...)
	if !strings.Contains(output, `"id":"accepted-report"`) || !strings.Contains(output, `"revision":4`) {
		t.Fatalf("memory output = %q", output)
	}
	output = runWorkroom(append([]string{"delete", "research"}, append(common, "-revision", "4")...)...)
	if !strings.Contains(output, `"deleted":true`) || !strings.Contains(output, `"project_id":"research"`) {
		t.Fatalf("delete output = %q", output)
	}
}

func TestWorkroomCommandsRejectIncompleteOrUnknownForms(t *testing.T) {
	tests := [][]string{
		nil,
		{"unknown"},
		{"session"},
		{"artifact"},
		{"memory"},
		{"create"},
		{"list", "-tenant-id", "tenant-a", "-limit", "0"},
		{"show"},
		{"delete", "research", "-tenant-id", "tenant-a"},
		{"session", "create", "research", "-tenant-id", "tenant-a"},
		{"artifact", "add", "research", "-tenant-id", "tenant-a"},
		{"memory", "add", "research", "-tenant-id", "tenant-a"},
		{"create", "research", "-tenant-id", "tenant-a"},
		{"list", "-tenant-id", "tenant-a"},
		{"show", "research", "-tenant-id", "tenant-a"},
		{"delete", "research", "-tenant-id", "tenant-a", "-revision", "1"},
		{"session", "create", "research", "-tenant-id", "tenant-a", "-id", "session", "-title", "Session"},
		{"artifact", "add", "research", "-tenant-id", "tenant-a", "-session", "session", "-id", "artifact",
			"-name", "Artifact", "-media-type", "text/plain", "-bytes", "1", "-sha256", "sha256:" + strings.Repeat("a", 64), "-ref", "object"},
		{"memory", "add", "research", "-tenant-id", "tenant-a", "-id", "memory", "-title", "Memory", "-artifact", "artifact"},
		{"create", "research", "-unknown"},
		{"list", "-unknown"},
		{"show", "research", "-unknown"},
		{"delete", "research", "-unknown"},
		{"session", "create", "research", "-unknown"},
		{"artifact", "add", "research", "-unknown"},
		{"memory", "add", "research", "-unknown"},
	}
	for _, arguments := range tests {
		if err := workroomCommand(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("workroomCommand(%q) unexpectedly succeeded", arguments)
		}
	}
}

func TestWorkroomCommandsReturnControlFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer admin-secret" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"error":"unavailable","message":"maintenance"}`))
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenPath, []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"-control-url", server.URL, "-token-file", tokenPath, "-tenant-id", "tenant-a"}
	tests := [][]string{
		append([]string{"create", "research"}, common...),
		append([]string{"list"}, common...),
		append([]string{"show", "research"}, common...),
		append([]string{"delete", "research"}, append(common, "-revision", "1")...),
		append([]string{"session", "create", "research"}, append(common, "-id", "session", "-title", "Session")...),
	}
	for _, arguments := range tests {
		if err := workroomCommand(arguments, &bytes.Buffer{}); err == nil ||
			!strings.Contains(err.Error(), "maintenance") {
			t.Fatalf("workroomCommand(%q) error = %v", arguments, err)
		}
	}
}
