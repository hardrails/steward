package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentcatalog"
)

type agentCatalogCLIFixture struct {
	releaseFixture agentReleaseCLIFixture
	curatorPrivate string
	curatorPublic  string
	manifestPath   string
	catalogPath    string
	source         agentCatalogSource
}

func TestAgentCatalogIssueVerifyBrowseAndCompare(t *testing.T) {
	fixture := newAgentCatalogCLIFixture(t)
	var issued bytes.Buffer
	if err := run(fixture.issueArguments(), &issued, &bytes.Buffer{}); err != nil {
		t.Fatalf("issue agent catalog: %v", err)
	}
	info, err := os.Stat(fixture.catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("catalog mode = %o, want 0600", info.Mode().Perm())
	}
	issuedResult := decodeAgentCatalogResult(t, issued.Bytes())
	if !issuedResult.Valid || issuedResult.Operation != "issued" ||
		issuedResult.CatalogID != "offline-agents" || issuedResult.Revision != 3 ||
		issuedResult.Authority != agentcatalog.AuthorityDescriptiveOnly ||
		issuedResult.Count != 2 || len(issuedResult.Entries) != 2 ||
		issuedResult.Entries[0].EntryID != "hermes-next" ||
		issuedResult.Entries[1].EntryID != "hermes-primary" ||
		issuedResult.Entries[0].Profile.ID != "hermes-v1" ||
		issuedResult.Entries[0].Resources.MemoryBytes != 768<<20 ||
		!issuedResult.Entries[0].Capabilities.Inference ||
		issuedResult.Entries[0].CapsuleExpiresAt != fixture.releaseFixture.now.Add(8*time.Minute).Format(time.RFC3339) ||
		len(issuedResult.Entries[0].Artifacts) != 1 {
		t.Fatalf("issued result = %#v", issuedResult)
	}

	var verified bytes.Buffer
	if err := run(fixture.readArguments("verify"), &verified, &bytes.Buffer{}); err != nil {
		t.Fatalf("verify agent catalog: %v", err)
	}
	verifyResult := decodeAgentCatalogResult(t, verified.Bytes())
	if verifyResult.Operation != "verify" || verifyResult.Count != 2 ||
		len(verifyResult.Entries) != 0 ||
		verifyResult.EnvelopeDigest != issuedResult.EnvelopeDigest {
		t.Fatalf("verify result = %#v", verifyResult)
	}

	var listed bytes.Buffer
	listArguments := append(fixture.readArguments("list"), "-status", agentcatalog.StatusApproved)
	if err := run(listArguments, &listed, &bytes.Buffer{}); err != nil {
		t.Fatalf("list agent catalog: %v", err)
	}
	listResult := decodeAgentCatalogResult(t, listed.Bytes())
	if listResult.Count != 1 || len(listResult.Entries) != 1 ||
		listResult.Entries[0].EntryID != "hermes-primary" {
		t.Fatalf("list result = %#v", listResult)
	}

	var searched bytes.Buffer
	searchArguments := append(fixture.readArguments("search"), "-query", "capability:inference")
	if err := run(searchArguments, &searched, &bytes.Buffer{}); err != nil {
		t.Fatalf("search agent catalog: %v", err)
	}
	searchResult := decodeAgentCatalogResult(t, searched.Bytes())
	if searchResult.Count != 1 || searchResult.Entries[0].EntryID != "hermes-next" {
		t.Fatalf("search result = %#v", searchResult)
	}

	var shown bytes.Buffer
	showArguments := append(fixture.readArguments("show"), "-entry-id", "hermes-primary")
	if err := run(showArguments, &shown, &bytes.Buffer{}); err != nil {
		t.Fatalf("show agent catalog entry: %v", err)
	}
	showResult := decodeAgentCatalogResult(t, shown.Bytes())
	if showResult.Entry == nil || showResult.Entry.ReleaseID != "hermes-workspace-audit" ||
		showResult.Entry.Bindings.SkillManifest.SHA256Digest == "" ||
		showResult.Entry.PublisherKeyDigest == "" {
		t.Fatalf("show result = %#v", showResult)
	}

	var compared bytes.Buffer
	compareArguments := append(
		fixture.readArguments("compare"),
		"-left-entry-id", "hermes-primary",
		"-right-entry-id", "hermes-next",
	)
	if err := run(compareArguments, &compared, &bytes.Buffer{}); err != nil {
		t.Fatalf("compare agent catalog entries: %v", err)
	}
	compareResult := decodeAgentCatalogResult(t, compared.Bytes())
	if compareResult.Comparison == nil || compareResult.Comparison.Equivalent ||
		len(compareResult.Comparison.Differences) == 0 ||
		compareResult.Comparison.Left.EntryID != "hermes-primary" ||
		compareResult.Comparison.Right.EntryID != "hermes-next" {
		t.Fatalf("compare result = %#v", compareResult)
	}
	differenceFields := make(map[string]struct{}, len(compareResult.Comparison.Differences))
	for _, difference := range compareResult.Comparison.Differences {
		differenceFields[difference.Field] = struct{}{}
	}
	for _, field := range []string{
		"resources.memory_bytes",
		"capabilities.inference",
		"capsule.expires_at",
	} {
		if _, exists := differenceFields[field]; !exists {
			t.Fatalf("compare result omits %q: %#v", field, compareResult.Comparison)
		}
	}
}

func TestAgentCatalogIssueChecksEveryExternalBinding(t *testing.T) {
	for _, test := range []struct {
		name      string
		path      func(agentCatalogCLIFixture) string
		change    []byte
		wantError string
	}{
		{
			name: "archive",
			path: func(fixture agentCatalogCLIFixture) string {
				return fixture.releaseFixture.archivePath
			},
			change:    []byte("trailing archive drift"),
			wantError: "inspect archive",
		},
		{
			name: "skill manifest",
			path: func(fixture agentCatalogCLIFixture) string {
				return fixture.releaseFixture.skillManifestPath
			},
			change:    []byte(`{"changed":true}`),
			wantError: "skill manifest bytes",
		},
		{
			name: "qualification evidence",
			path: func(fixture agentCatalogCLIFixture) string {
				return fixture.releaseFixture.qualificationEvidencePath
			},
			change:    []byte(`{"changed":true}`),
			wantError: "qualification evidence bytes",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentCatalogCLIFixture(t)
			path := test.path(fixture)
			if test.name == "archive" {
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(test.change); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, test.change, 0o600); err != nil {
				t.Fatal(err)
			}
			err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("issue with changed %s err = %v", test.name, err)
			}
			if _, err := os.Stat(fixture.catalogPath); !os.IsNotExist(err) {
				t.Fatalf("invalid catalog output exists: %v", err)
			}
		})
	}
}

func TestAgentCatalogRejectsUntrustedInputsAndLooseSelection(t *testing.T) {
	t.Run("publisher key substitution", func(t *testing.T) {
		fixture := newAgentCatalogCLIFixture(t)
		otherPrivate := filepath.Join(fixture.releaseFixture.directory, "other.private.pem")
		otherPublic := filepath.Join(fixture.releaseFixture.directory, "other.public")
		if err := run([]string{
			"keygen", "-private-out", otherPrivate, "-public-out", otherPublic, "-key-id", "publisher-a",
		}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		fixture.source.Entries[0].PublisherPublicKey = filepath.Base(otherPublic)
		fixture.writeSource(t)
		err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "verify agent release") {
			t.Fatalf("publisher substitution err = %v", err)
		}
	})

	t.Run("unknown manifest field", func(t *testing.T) {
		fixture := newAgentCatalogCLIFixture(t)
		raw := []byte(`{"schema_version":"steward.agent-catalog-source.v1","catalog_id":"x","revision":1,"entries":[],"execute":"yes"}`)
		if err := os.WriteFile(fixture.manifestPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "unknown JSON field") {
			t.Fatalf("unknown field err = %v", err)
		}
	})

	t.Run("selection flags", func(t *testing.T) {
		fixture := newAgentCatalogCLIFixture(t)
		if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		tests := [][]string{
			append(fixture.readArguments("verify"), "-status", "approved"),
			append(fixture.readArguments("list"), "-query", "Hermes"),
			append(fixture.readArguments("search"), "-query", " trailing "),
			append(fixture.readArguments("show"), "-entry-id", "bad/id"),
			append(fixture.readArguments("compare"), "-left-entry-id", "same", "-right-entry-id", "same"),
		}
		for _, arguments := range tests {
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatalf("loose selection accepted: %#v", arguments)
			}
		}
	})

	for _, arguments := range [][]string{
		{"agent-catalog"},
		{"agent-catalog", "unknown"},
		{"agent-catalog", "issue"},
		{"agent-catalog", "verify"},
		{"agent-catalog", "search"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("incomplete command accepted: %#v", arguments)
		}
	}
}

func newAgentCatalogCLIFixture(t *testing.T) agentCatalogCLIFixture {
	t.Helper()
	releaseFixture := newAgentReleaseCLIFixture(t)
	if err := run(releaseFixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("issue release fixture: %v", err)
	}
	secondRelease := filepath.Join(releaseFixture.directory, "agent-release-next.dsse.json")
	secondCapsulePath := filepath.Join(releaseFixture.directory, "capsule-next.dsse.json")
	publisherPrivate, err := readPrivateKey(releaseFixture.privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	secondCapsule := releaseFixture.capsule(t)
	secondCapsule.CapsuleID = "hermes-workspace-audit-next"
	secondCapsule.Resources.MemoryBytes = 768 << 20
	secondCapsule.Capabilities.Inference = true
	secondCapsule.ExpiresAt = releaseFixture.now.Add(8 * time.Minute).Format(time.RFC3339)
	writeSignedJSON(
		t,
		secondCapsulePath,
		admission.CapsulePayloadType,
		secondCapsule,
		"publisher-a",
		publisherPrivate,
	)
	secondArguments := append([]string(nil), releaseFixture.issueArguments()...)
	secondArguments[argumentValueIndex(t, secondArguments, "-capsule")] = secondCapsulePath
	secondArguments[argumentValueIndex(t, secondArguments, "-release-id")] = "hermes-workspace-audit-next"
	secondArguments[argumentValueIndex(t, secondArguments, "-title")] = "Second Hermes audit"
	secondArguments[argumentValueIndex(t, secondArguments, "-out")] = secondRelease
	if err := run(secondArguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("issue second release fixture: %v", err)
	}
	curatorPrivate := filepath.Join(releaseFixture.directory, "curator.private.pem")
	curatorPublic := filepath.Join(releaseFixture.directory, "curator.public")
	if err := run([]string{
		"keygen",
		"-private-out", curatorPrivate,
		"-public-out", curatorPublic,
		"-key-id", "curator-a",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	source := agentCatalogSource{
		SchemaVersion: agentCatalogSourceSchemaV1,
		CatalogID:     "offline-agents",
		Revision:      3,
		Entries: []agentCatalogSourceEntry{
			{
				EntryID: "hermes-primary", Status: agentcatalog.StatusApproved,
				Release:               filepath.Base(releaseFixture.outputPath),
				PublisherKeyID:        "publisher-a",
				PublisherPublicKey:    filepath.Base(releaseFixture.publicKeyPath),
				Archive:               filepath.Base(releaseFixture.archivePath),
				SkillManifest:         filepath.Base(releaseFixture.skillManifestPath),
				QualificationEvidence: filepath.Base(releaseFixture.qualificationEvidencePath),
			},
			{
				EntryID: "hermes-next", Status: agentcatalog.StatusCandidate,
				Release:               filepath.Base(secondRelease),
				PublisherKeyID:        "publisher-a",
				PublisherPublicKey:    filepath.Base(releaseFixture.publicKeyPath),
				Archive:               filepath.Base(releaseFixture.archivePath),
				SkillManifest:         filepath.Base(releaseFixture.skillManifestPath),
				QualificationEvidence: filepath.Base(releaseFixture.qualificationEvidencePath),
			},
		},
	}
	fixture := agentCatalogCLIFixture{
		releaseFixture: releaseFixture,
		curatorPrivate: curatorPrivate,
		curatorPublic:  curatorPublic,
		manifestPath:   filepath.Join(releaseFixture.directory, "catalog-source.json"),
		catalogPath:    filepath.Join(releaseFixture.directory, "agent-catalog.dsse.json"),
		source:         source,
	}
	fixture.writeSource(t)
	return fixture
}

func (fixture agentCatalogCLIFixture) issueArguments() []string {
	return []string{
		"agent-catalog", "issue",
		"-manifest", fixture.manifestPath,
		"-key", fixture.curatorPrivate,
		"-key-id", "curator-a",
		"-out", fixture.catalogPath,
	}
}

func (fixture agentCatalogCLIFixture) readArguments(operation string) []string {
	return []string{
		"agent-catalog", operation,
		"-in", fixture.catalogPath,
		"-public-key", fixture.curatorPublic,
		"-key-id", "curator-a",
	}
}

func (fixture agentCatalogCLIFixture) writeSource(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func decodeAgentCatalogResult(t *testing.T, raw []byte) agentCatalogResult {
	t.Helper()
	var output agentCatalogResult
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatalf("decode catalog output: %v\n%s", err, raw)
	}
	if output.SchemaVersion != agentCatalogResultSchemaV1 {
		t.Fatalf("result schema = %q", output.SchemaVersion)
	}
	return output
}
