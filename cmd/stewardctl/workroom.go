package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
)

func workroomCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return workroomUsageError()
	}
	switch arguments[0] {
	case "create":
		return createWorkroom(arguments[1:], stdout)
	case "list":
		return listWorkrooms(arguments[1:], stdout)
	case "show":
		return showWorkroom(arguments[1:], stdout)
	case "delete":
		return deleteWorkroom(arguments[1:], stdout)
	case "session":
		if len(arguments) > 1 && arguments[1] == "create" {
			return createWorkroomSession(arguments[2:], stdout)
		}
	case "artifact":
		if len(arguments) > 1 && arguments[1] == "add" {
			return addWorkroomArtifact(arguments[2:], stdout)
		}
	case "memory":
		if len(arguments) > 1 && arguments[1] == "add" {
			return addWorkroomMemory(arguments[2:], stdout)
		}
	}
	return workroomUsageError()
}

func workroomUsageError() error {
	return errors.New("workroom requires create, list, show, delete, session create, artifact add, or memory add")
}

func createWorkroom(arguments []string, stdout io.Writer) error {
	projectID, arguments := deploymentLeadingName(arguments)
	flags := flag.NewFlagSet("workroom create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	name := flags.String("name", "", "human-readable project name; defaults to the project ID")
	description := flags.String("description", "", "short project purpose")
	agentRef := flags.String("agent", "", "default deployed agent reference")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if projectID == "" || *tenantID == "" || flags.NArg() != 0 {
		return errors.New("workroom create requires PROJECT and a tenant")
	}
	if *name == "" {
		*name = projectID
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	project, err := client.ApplyWorkroomProject(ctx, controlstore.WorkroomProject{
		TenantID: *tenantID, ID: projectID, Name: *name, Description: *description, AgentRef: *agentRef,
		Sessions: []controlstore.WorkroomSession{}, Artifacts: []controlstore.WorkroomArtifact{},
		MemoryRefs: []controlstore.WorkroomMemoryReference{},
	}, 0)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, project)
}

func listWorkrooms(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("workroom list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	after := flags.String("after", "", "exclusive project ID cursor")
	limit := flags.Int("limit", 100, "maximum projects to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *limit <= 0 || *limit > 500 || flags.NArg() != 0 {
		return errors.New("workroom list requires a tenant and a limit between 1 and 500")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListWorkroomProjects(ctx, *tenantID, *after, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, page)
}

func showWorkroom(arguments []string, stdout io.Writer) error {
	projectID, arguments := deploymentLeadingName(arguments)
	flags := flag.NewFlagSet("workroom show", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if projectID == "" || *tenantID == "" || flags.NArg() != 0 {
		return errors.New("workroom show requires PROJECT and a tenant")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	project, err := client.GetWorkroomProject(ctx, *tenantID, projectID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, project)
}

func deleteWorkroom(arguments []string, stdout io.Writer) error {
	projectID, arguments := deploymentLeadingName(arguments)
	flags := flag.NewFlagSet("workroom delete", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	revision := flags.Uint64("revision", 0, "exact current project revision")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if projectID == "" || *tenantID == "" || *revision == 0 || flags.NArg() != 0 {
		return errors.New("workroom delete requires PROJECT, a tenant, and -revision")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.DeleteWorkroomProject(ctx, *tenantID, projectID, *revision); err != nil {
		return err
	}
	return writeControlJSON(stdout, map[string]any{"project_id": projectID, "deleted": true})
}

func createWorkroomSession(arguments []string, stdout io.Writer) error {
	projectID, arguments := deploymentLeadingName(arguments)
	flags := flag.NewFlagSet("workroom session create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	sessionID := flags.String("id", "", "stable session ID")
	title := flags.String("title", "", "session title")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if projectID == "" || *tenantID == "" || *sessionID == "" || *title == "" || flags.NArg() != 0 {
		return errors.New("workroom session create requires PROJECT, a tenant, -id, and -title")
	}
	return updateWorkroom(arguments, stdout, common, *tenantID, projectID, func(project *controlstore.WorkroomProject) error {
		for _, session := range project.Sessions {
			if session.ID == *sessionID {
				return errors.New("workroom session already exists")
			}
		}
		project.Sessions = append(project.Sessions, controlstore.WorkroomSession{
			ID: *sessionID, Title: *title, State: "active", TaskIDs: []string{},
		})
		return nil
	})
}

func addWorkroomArtifact(arguments []string, stdout io.Writer) error {
	projectID, arguments := deploymentLeadingName(arguments)
	flags := flag.NewFlagSet("workroom artifact add", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	sessionID := flags.String("session", "", "owning session ID")
	taskID := flags.String("task", "", "producing task ID")
	artifactID := flags.String("id", "", "stable artifact ID")
	name := flags.String("name", "", "display name")
	mediaType := flags.String("media-type", "", "IANA media type")
	size := flags.Int64("bytes", -1, "artifact byte length")
	digest := flags.String("sha256", "", "sha256: digest")
	externalRef := flags.String("ref", "", "opaque S3-compatible or operator storage reference")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if projectID == "" || *tenantID == "" || *sessionID == "" || *artifactID == "" || *name == "" ||
		*mediaType == "" || *size < 0 || *digest == "" || *externalRef == "" || flags.NArg() != 0 {
		return errors.New("workroom artifact add requires PROJECT, tenant, session, id, name, media type, bytes, sha256, and external ref")
	}
	return updateWorkroom(arguments, stdout, common, *tenantID, projectID, func(project *controlstore.WorkroomProject) error {
		project.Artifacts = append(project.Artifacts, controlstore.WorkroomArtifact{
			ID: *artifactID, SessionID: *sessionID, TaskID: *taskID, Name: *name,
			MediaType: *mediaType, Bytes: *size, SHA256: *digest, ExternalRef: *externalRef,
		})
		return nil
	})
}

func addWorkroomMemory(arguments []string, stdout io.Writer) error {
	projectID, arguments := deploymentLeadingName(arguments)
	flags := flag.NewFlagSet("workroom memory add", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	memoryID := flags.String("id", "", "stable memory reference ID")
	title := flags.String("title", "", "human-readable memory label")
	artifactID := flags.String("artifact", "", "retained artifact ID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if projectID == "" || *tenantID == "" || *memoryID == "" || *title == "" || *artifactID == "" || flags.NArg() != 0 {
		return errors.New("workroom memory add requires PROJECT, tenant, id, title, and artifact")
	}
	return updateWorkroom(arguments, stdout, common, *tenantID, projectID, func(project *controlstore.WorkroomProject) error {
		project.MemoryRefs = append(project.MemoryRefs, controlstore.WorkroomMemoryReference{
			ID: *memoryID, Title: *title, ArtifactID: *artifactID,
		})
		return nil
	})
}

func updateWorkroom(
	_ []string,
	stdout io.Writer,
	common controlFlags,
	tenantID, projectID string,
	change func(*controlstore.WorkroomProject) error,
) error {
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	project, err := client.GetWorkroomProject(ctx, tenantID, projectID)
	if err != nil {
		return err
	}
	revision := project.Revision
	if err := change(&project); err != nil {
		return err
	}
	project, err = client.ApplyWorkroomProject(ctx, project, revision)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, project)
}
