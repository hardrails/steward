package controlstore

import (
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/controlauth"
)

const (
	MaxWorkroomProjects             = 1024
	MaxWorkroomProjectsPerTenant    = 128
	MaxWorkroomSessionsPerProject   = 64
	MaxWorkroomTasksPerSession      = 256
	MaxWorkroomArtifactsPerProject  = 256
	MaxWorkroomMemoryRefsPerProject = 64
)

type WorkroomProject struct {
	TenantID    string                    `json:"tenant_id"`
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description,omitempty"`
	AgentRef    string                    `json:"agent_ref,omitempty"`
	Skills      []string                  `json:"skills,omitempty"`
	Sessions    []WorkroomSession         `json:"sessions"`
	Artifacts   []WorkroomArtifact        `json:"artifacts"`
	MemoryRefs  []WorkroomMemoryReference `json:"memory_refs"`
	Revision    uint64                    `json:"revision"`
	CreatedAt   string                    `json:"created_at"`
	UpdatedAt   string                    `json:"updated_at"`
}

type WorkroomSession struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	State     string   `json:"state"`
	TaskIDs   []string `json:"task_ids"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

type WorkroomArtifact struct {
	ID          string `json:"id"`
	SessionID   string `json:"session_id"`
	TaskID      string `json:"task_id,omitempty"`
	Name        string `json:"name"`
	MediaType   string `json:"media_type"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	ExternalRef string `json:"external_ref"`
	CreatedAt   string `json:"created_at"`
}

// WorkroomMemoryReference points at retained, operator-selected evidence. It
// never stores a prompt, transcript, secret, or model-created authority.
type WorkroomMemoryReference struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	ArtifactID string `json:"artifact_id"`
	CreatedAt  string `json:"created_at"`
}

func (project WorkroomProject) Validate() error {
	if !validWorkroomProject(project) {
		return errors.New("workroom project is invalid")
	}
	return nil
}

func (store *Store) ApplyWorkroomProject(
	actor controlauth.Identity,
	project WorkroomProject,
	expectedRevision uint64,
	now time.Time,
) (WorkroomProject, bool, error) {
	if store == nil {
		return WorkroomProject{}, false, ErrUnavailable
	}
	if now.IsZero() || !controlauth.AuthorizedTenant(actor, project.TenantID) {
		return WorkroomProject{}, false, ErrNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return WorkroomProject{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return WorkroomProject{}, false, err
	}
	tenant, found := store.current.tenants[project.TenantID]
	if !found || !tenant.Active {
		return WorkroomProject{}, false, ErrNotFound
	}
	key := workroomProjectKey(project.TenantID, project.ID)
	existing, exists := store.current.workroomProjects[key]
	if exists && existing.Revision != expectedRevision || !exists && expectedRevision != 0 {
		return WorkroomProject{}, false, ErrConflict
	}
	if !exists {
		count := 0
		for _, retained := range store.current.workroomProjects {
			if retained.TenantID == project.TenantID {
				count++
			}
		}
		if len(store.current.workroomProjects) >= MaxWorkroomProjects || count >= MaxWorkroomProjectsPerTenant {
			return WorkroomProject{}, false, ErrCapacityExceeded
		}
		project.Revision = 1
		project.CreatedAt = canonicalTimestamp(now)
	} else {
		project.Revision = existing.Revision + 1
		project.CreatedAt = existing.CreatedAt
	}
	project.UpdatedAt = canonicalTimestamp(now)
	project.Skills = canonicalStringSet(project.Skills)
	project = normalizeWorkroomNested(project, existing, now)
	project.Sessions = canonicalWorkroomSessions(project.Sessions)
	project.Artifacts = canonicalWorkroomArtifacts(project.Artifacts)
	project.MemoryRefs = canonicalWorkroomMemoryRefs(project.MemoryRefs)
	if !validWorkroomProject(project) {
		return WorkroomProject{}, false, invalid("workroom project is invalid or exceeds a bound")
	}
	if exists && workroomProjectsEqual(existing, project, true) {
		return cloneWorkroomProject(existing), false, nil
	}
	if err := store.applyMutationsLocked(workroomProjectMutation(project)); err != nil {
		return WorkroomProject{}, false, err
	}
	return cloneWorkroomProject(project), true, nil
}

func normalizeWorkroomNested(project, existing WorkroomProject, now time.Time) WorkroomProject {
	created := canonicalTimestamp(now)
	existingSessions := make(map[string]WorkroomSession, len(existing.Sessions))
	for _, session := range existing.Sessions {
		existingSessions[session.ID] = session
	}
	for index := range project.Sessions {
		retained, found := existingSessions[project.Sessions[index].ID]
		if project.Sessions[index].CreatedAt == "" {
			project.Sessions[index].CreatedAt = created
			if found {
				project.Sessions[index].CreatedAt = retained.CreatedAt
			}
		}
		if project.Sessions[index].UpdatedAt == "" {
			project.Sessions[index].UpdatedAt = created
		}
		if project.Sessions[index].State == "" {
			project.Sessions[index].State = "active"
		}
		if project.Sessions[index].TaskIDs == nil {
			project.Sessions[index].TaskIDs = []string{}
		}
	}
	existingArtifacts := make(map[string]WorkroomArtifact, len(existing.Artifacts))
	for _, artifact := range existing.Artifacts {
		existingArtifacts[artifact.ID] = artifact
	}
	for index := range project.Artifacts {
		if project.Artifacts[index].CreatedAt == "" {
			project.Artifacts[index].CreatedAt = created
			if retained, found := existingArtifacts[project.Artifacts[index].ID]; found {
				project.Artifacts[index].CreatedAt = retained.CreatedAt
			}
		}
	}
	existingMemory := make(map[string]WorkroomMemoryReference, len(existing.MemoryRefs))
	for _, ref := range existing.MemoryRefs {
		existingMemory[ref.ID] = ref
	}
	for index := range project.MemoryRefs {
		if project.MemoryRefs[index].CreatedAt == "" {
			project.MemoryRefs[index].CreatedAt = created
			if retained, found := existingMemory[project.MemoryRefs[index].ID]; found {
				project.MemoryRefs[index].CreatedAt = retained.CreatedAt
			}
		}
	}
	if project.Sessions == nil {
		project.Sessions = []WorkroomSession{}
	}
	if project.Artifacts == nil {
		project.Artifacts = []WorkroomArtifact{}
	}
	if project.MemoryRefs == nil {
		project.MemoryRefs = []WorkroomMemoryReference{}
	}
	return project
}

func (store *Store) ListWorkroomProjects(actor controlauth.Identity, tenantID string) ([]WorkroomProject, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return nil, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return nil, ErrNotFound
	}
	result := make([]WorkroomProject, 0)
	for _, project := range store.current.workroomProjects {
		if project.TenantID == tenantID {
			result = append(result, cloneWorkroomProject(project))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (store *Store) GetWorkroomProject(
	actor controlauth.Identity,
	tenantID, projectID string,
) (WorkroomProject, error) {
	if store == nil {
		return WorkroomProject{}, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return WorkroomProject{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return WorkroomProject{}, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return WorkroomProject{}, ErrNotFound
	}
	project, found := store.current.workroomProjects[workroomProjectKey(tenantID, projectID)]
	if !found {
		return WorkroomProject{}, ErrNotFound
	}
	return cloneWorkroomProject(project), nil
}

func (store *Store) DeleteWorkroomProject(
	actor controlauth.Identity,
	tenantID, projectID string,
	expectedRevision uint64,
) error {
	if store == nil {
		return ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return ErrNotFound
	}
	key := workroomProjectKey(tenantID, projectID)
	project, found := store.current.workroomProjects[key]
	if !found {
		return ErrNotFound
	}
	if project.Revision != expectedRevision {
		return ErrConflict
	}
	for _, task := range store.current.taskRequests {
		if task.TenantID == tenantID && task.ProjectID == projectID {
			return ErrConflict
		}
	}
	return store.applyMutationsLocked(workroomProjectDeleteMutation(tenantID, projectID))
}

func validWorkroomProject(project WorkroomProject) bool {
	if !validRecordID(project.TenantID, 128) || !validRecordID(project.ID, 128) ||
		!validWorkroomText(project.Name, 1, 128) || !validWorkroomText(project.Description, 0, 2048) ||
		project.AgentRef != "" && !validRecordID(project.AgentRef, 256) ||
		project.Revision == 0 || !validTimestamp(project.CreatedAt) || !validTimestamp(project.UpdatedAt) ||
		timestampBefore(project.UpdatedAt, project.CreatedAt) ||
		len(project.Skills) > 32 || len(project.Sessions) > MaxWorkroomSessionsPerProject ||
		len(project.Artifacts) > MaxWorkroomArtifactsPerProject || len(project.MemoryRefs) > MaxWorkroomMemoryRefsPerProject ||
		project.Sessions == nil || project.Artifacts == nil || project.MemoryRefs == nil {
		return false
	}
	if !equalStrings(project.Skills, canonicalStringSet(project.Skills)) {
		return false
	}
	for _, skill := range project.Skills {
		if !validRecordID(skill, 128) {
			return false
		}
	}
	sessions := make(map[string]struct{}, len(project.Sessions))
	tasks := make(map[string]struct{})
	for _, session := range project.Sessions {
		if !validRecordID(session.ID, 128) || !validWorkroomText(session.Title, 1, 256) ||
			session.State != "active" && session.State != "archived" ||
			!validTimestamp(session.CreatedAt) || !validTimestamp(session.UpdatedAt) ||
			timestampBefore(session.UpdatedAt, session.CreatedAt) || len(session.TaskIDs) > MaxWorkroomTasksPerSession ||
			session.TaskIDs == nil || !equalStrings(session.TaskIDs, canonicalStringSet(session.TaskIDs)) {
			return false
		}
		if _, duplicate := sessions[session.ID]; duplicate {
			return false
		}
		sessions[session.ID] = struct{}{}
		for _, taskID := range session.TaskIDs {
			if !validRecordID(taskID, 128) {
				return false
			}
			if _, duplicate := tasks[taskID]; duplicate {
				return false
			}
			tasks[taskID] = struct{}{}
		}
	}
	artifacts := make(map[string]struct{}, len(project.Artifacts))
	for _, artifact := range project.Artifacts {
		if !validRecordID(artifact.ID, 128) || !validRecordID(artifact.SessionID, 128) ||
			artifact.TaskID != "" && !validRecordID(artifact.TaskID, 128) ||
			!validWorkroomText(artifact.Name, 1, 256) || !validWorkroomText(artifact.MediaType, 1, 128) ||
			artifact.Bytes < 0 || !validSHA256Digest(artifact.SHA256) ||
			!validWorkroomText(artifact.ExternalRef, 1, 2048) || !validTimestamp(artifact.CreatedAt) {
			return false
		}
		if _, found := sessions[artifact.SessionID]; !found {
			return false
		}
		if artifact.TaskID != "" {
			if _, found := tasks[artifact.TaskID]; !found {
				return false
			}
		}
		if _, duplicate := artifacts[artifact.ID]; duplicate {
			return false
		}
		artifacts[artifact.ID] = struct{}{}
	}
	memory := make(map[string]struct{}, len(project.MemoryRefs))
	for _, ref := range project.MemoryRefs {
		if !validRecordID(ref.ID, 128) || !validWorkroomText(ref.Title, 1, 256) ||
			!validRecordID(ref.ArtifactID, 128) || !validTimestamp(ref.CreatedAt) {
			return false
		}
		if _, found := artifacts[ref.ArtifactID]; !found {
			return false
		}
		if _, duplicate := memory[ref.ID]; duplicate {
			return false
		}
		memory[ref.ID] = struct{}{}
	}
	return true
}

func validWorkroomText(value string, min, max int) bool {
	return utf8.ValidString(value) && len(value) >= min && len(value) <= max &&
		!strings.ContainsAny(value, "\r\n\x00") && (min == 0 || strings.TrimSpace(value) == value)
}

func canonicalWorkroomSessions(values []WorkroomSession) []WorkroomSession {
	result := make([]WorkroomSession, len(values))
	copy(result, values)
	for index := range result {
		result[index].TaskIDs = canonicalStringSet(result[index].TaskIDs)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func canonicalWorkroomArtifacts(values []WorkroomArtifact) []WorkroomArtifact {
	result := make([]WorkroomArtifact, len(values))
	copy(result, values)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func canonicalWorkroomMemoryRefs(values []WorkroomMemoryReference) []WorkroomMemoryReference {
	result := make([]WorkroomMemoryReference, len(values))
	copy(result, values)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func cloneWorkroomProject(project WorkroomProject) WorkroomProject {
	project.Skills = cloneStrings(project.Skills)
	sessions := project.Sessions
	project.Sessions = make([]WorkroomSession, len(project.Sessions))
	copy(project.Sessions, sessions)
	for index := range project.Sessions {
		project.Sessions[index].TaskIDs = cloneStrings(project.Sessions[index].TaskIDs)
	}
	artifacts := project.Artifacts
	project.Artifacts = make([]WorkroomArtifact, len(artifacts))
	copy(project.Artifacts, artifacts)
	memoryRefs := project.MemoryRefs
	project.MemoryRefs = make([]WorkroomMemoryReference, len(memoryRefs))
	copy(project.MemoryRefs, memoryRefs)
	return project
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func workroomProjectsEqual(left, right WorkroomProject, ignoreRevisionAndUpdated bool) bool {
	if ignoreRevisionAndUpdated {
		right.Revision, right.CreatedAt, right.UpdatedAt = left.Revision, left.CreatedAt, left.UpdatedAt
	}
	left = cloneWorkroomProject(left)
	right = cloneWorkroomProject(right)
	return left.TenantID == right.TenantID && left.ID == right.ID && left.Name == right.Name &&
		left.Description == right.Description && left.AgentRef == right.AgentRef &&
		equalStrings(left.Skills, right.Skills) && workroomSessionsEqual(left.Sessions, right.Sessions) &&
		workroomArtifactsEqual(left.Artifacts, right.Artifacts) && workroomMemoryEqual(left.MemoryRefs, right.MemoryRefs) &&
		left.Revision == right.Revision && left.CreatedAt == right.CreatedAt && left.UpdatedAt == right.UpdatedAt
}

func workroomSessionsEqual(left, right []WorkroomSession) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID || left[index].Title != right[index].Title ||
			left[index].State != right[index].State || left[index].CreatedAt != right[index].CreatedAt ||
			left[index].UpdatedAt != right[index].UpdatedAt || !equalStrings(left[index].TaskIDs, right[index].TaskIDs) {
			return false
		}
	}
	return true
}

func workroomArtifactsEqual(left, right []WorkroomArtifact) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func workroomMemoryEqual(left, right []WorkroomMemoryReference) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func canonicalStringSet(values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	copy(result, values)
	sort.Strings(result)
	compacted := result[:0]
	for _, value := range result {
		if len(compacted) == 0 || compacted[len(compacted)-1] != value {
			compacted = append(compacted, value)
		}
	}
	return compacted
}

func workroomProjectKey(tenantID, projectID string) string { return tenantID + "\x00" + projectID }

func workroomSessionContainsTask(project WorkroomProject, sessionID, taskID string) bool {
	for _, session := range project.Sessions {
		if session.ID == sessionID {
			for _, retainedTaskID := range session.TaskIDs {
				if retainedTaskID == taskID {
					return true
				}
			}
			return false
		}
	}
	return false
}

func workroomProjectMutation(project WorkroomProject) mutation {
	cloned := cloneWorkroomProject(project)
	return mutation{Kind: mutationWorkroomProject, WorkroomProject: &cloned}
}

func workroomProjectDeleteMutation(tenantID, projectID string) mutation {
	return mutation{
		Kind:               mutationWorkroomProjectDelete,
		WorkroomProjectRef: &workroomProjectReference{TenantID: tenantID, ProjectID: projectID},
	}
}
