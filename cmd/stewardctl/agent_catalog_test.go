package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentcatalog"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
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
		issuedResult.Entries[0].CapsuleID != "hermes-workspace-audit-next" ||
		!slices.Equal(issuedResult.Entries[0].Command, []string{"serve", "--candidate", "line one\nline two"}) ||
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
	differences := make(map[string]agentCatalogDifference, len(compareResult.Comparison.Differences))
	for _, difference := range compareResult.Comparison.Differences {
		differences[difference.Field] = difference
	}
	for _, field := range []string{
		"capsule.id",
		"command",
		"resources.memory_bytes",
		"capabilities.inference",
		"capsule.expires_at",
	} {
		if _, exists := differences[field]; !exists {
			t.Fatalf("compare result omits %q: %#v", field, compareResult.Comparison)
		}
	}
	commandDifference := differences["command"]
	var leftCommand, rightCommand []string
	if err := json.Unmarshal([]byte(commandDifference.Left), &leftCommand); err != nil {
		t.Fatalf("left command difference is not canonical JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(commandDifference.Right), &rightCommand); err != nil {
		t.Fatalf("right command difference is not canonical JSON: %v", err)
	}
	if !slices.Equal(leftCommand, compareResult.Comparison.Left.Command) ||
		!slices.Equal(rightCommand, compareResult.Comparison.Right.Command) {
		t.Fatalf("command difference is ambiguous: %#v", commandDifference)
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

func TestCompareAgentCatalogEntriesIncludesCanaryRequest(t *testing.T) {
	left := agentcatalog.VerifiedEntry{}
	right := left
	left.Release.Release.Canary.Request.Input = "left input"
	right.Release.Release.Canary.Request.Input = "right input"
	left.Release.Release.Canary.Request.SessionIDPrefix = "left-session"
	right.Release.Release.Canary.Request.SessionIDPrefix = "right-session"

	comparison := compareAgentCatalogEntries(left, right)
	if comparison.Equivalent {
		t.Fatal("different canary request recipes were reported equivalent")
	}
	differences := make(map[string]agentCatalogDifference, len(comparison.Differences))
	for _, difference := range comparison.Differences {
		differences[difference.Field] = difference
	}
	for field, want := range map[string]agentCatalogDifference{
		"canary.request.input": {
			Field: "canary.request.input", Left: "left input", Right: "right input",
		},
		"canary.request.session_id_prefix": {
			Field: "canary.request.session_id_prefix", Left: "left-session", Right: "right-session",
		},
	} {
		if got, exists := differences[field]; !exists || got != want {
			t.Fatalf("difference %q = %#v, want %#v", field, got, want)
		}
	}
}

func TestAgentCatalogIssuePreflightsSmallInputsBeforeArchiveInspection(t *testing.T) {
	fixture := newAgentCatalogCLIFixture(t)
	fixture.source.Entries[1].QualificationEvidence = "missing-qualification-evidence.json"
	fixture.writeSource(t)
	file, err := os.OpenFile(fixture.releaseFixture.archivePath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("archive drift that must not be inspected first"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	err = run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "read qualification evidence") ||
		strings.Contains(err.Error(), "inspect archive") {
		t.Fatalf("small-input preflight err = %v", err)
	}
}

func TestAgentCatalogIssueRejectsDuplicateReleaseIdentityBeforeArchiveInspection(t *testing.T) {
	fixture := newAgentCatalogCLIFixture(t)
	fixture.source.Entries[1].Release = fixture.source.Entries[0].Release
	for index := range fixture.source.Entries {
		fixture.source.Entries[index].Archive = "missing-archive.tar"
	}
	fixture.writeSource(t)
	err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil ||
		!strings.Contains(err.Error(), "duplicate publisher/release identity") ||
		strings.Contains(err.Error(), "inspect archive") {
		t.Fatalf("duplicate release identity err = %v", err)
	}
}

func TestAgentCatalogIssueRejectsAggregateArchiveBudgetBeforeInspection(t *testing.T) {
	fixture := newAgentCatalogCLIFixture(t)
	releaseRaw, err := os.ReadFile(fixture.releaseFixture.outputPath)
	if err != nil {
		t.Fatal(err)
	}
	publisherPublic, err := readPublicKey(fixture.releaseFixture.publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := agentrelease.Verify(
		releaseRaw,
		map[string]ed25519.PublicKey{"publisher-a": publisherPublic},
		fixture.releaseFixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	publisherPrivate, err := readPrivateKey(fixture.releaseFixture.privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	sourceEntries := make([]agentCatalogSourceEntry, 0, 4)
	for index := 0; index < 4; index++ {
		release := verified.Release
		release.ReleaseID = fmt.Sprintf("aggregate-budget-%d", index)
		release.Archive.SizeBytes = agentrelease.MaxArchiveBytes
		raw, err := agentrelease.Sign(
			release,
			"publisher-a",
			publisherPrivate,
			fixture.releaseFixture.now,
		)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(
			fixture.releaseFixture.directory,
			fmt.Sprintf("aggregate-budget-%d.release.dsse.json", index),
		)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		sourceEntries = append(sourceEntries, agentCatalogSourceEntry{
			EntryID:               fmt.Sprintf("aggregate-budget-%d", index),
			Status:                agentcatalog.StatusCandidate,
			Release:               filepath.Base(path),
			PublisherKeyID:        "publisher-a",
			PublisherPublicKey:    filepath.Base(fixture.releaseFixture.publicKeyPath),
			Archive:               "missing-archive.tar",
			SkillManifest:         filepath.Base(fixture.releaseFixture.skillManifestPath),
			QualificationEvidence: filepath.Base(fixture.releaseFixture.qualificationEvidencePath),
		})
	}
	fixture.source.Entries = sourceEntries
	fixture.writeSource(t)
	err = run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil ||
		!strings.Contains(err.Error(), "aggregate archive inspection budget") ||
		strings.Contains(err.Error(), "inspect archive") {
		t.Fatalf("aggregate archive budget err = %v", err)
	}
}

func TestAgentCatalogManifestPathsStayConfined(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*testing.T, *agentCatalogCLIFixture)
		wantError string
	}{
		{
			name: "absolute path",
			configure: func(_ *testing.T, fixture *agentCatalogCLIFixture) {
				fixture.source.Entries[0].Release = fixture.releaseFixture.outputPath
			},
			wantError: "path must be relative",
		},
		{
			name: "parent traversal",
			configure: func(_ *testing.T, fixture *agentCatalogCLIFixture) {
				fixture.source.Entries[0].Release = "../agent-release.dsse.json"
			},
			wantError: "must not contain a '..' component",
		},
		{
			name: "symlink parent escape",
			configure: func(t *testing.T, fixture *agentCatalogCLIFixture) {
				outside := t.TempDir()
				link := filepath.Join(fixture.releaseFixture.directory, "outside")
				if err := os.Symlink(outside, link); err != nil {
					t.Skipf("create symlink fixture: %v", err)
				}
				fixture.source.Entries[0].Release = filepath.Join("outside", "release.dsse.json")
			},
			wantError: "path escapes from parent",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentCatalogCLIFixture(t)
			test.configure(t, &fixture)
			fixture.writeSource(t)
			err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("confined path err = %v", err)
			}
		})
	}
}

func TestAgentCatalogInputRootSurvivesParentReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renaming an open directory is not portable on Windows")
	}
	parent := t.TempDir()
	directory := filepath.Join(parent, "catalog")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "catalog-source.json")
	if err := os.WriteFile(manifestPath, []byte(`{"manifest":"inside"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "input"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, _, err := openAgentCatalogInputRoot(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	moved := filepath.Join(parent, "moved")
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "input"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, directory); err != nil {
		t.Fatal(err)
	}
	raw, err := securefile.ReadRoot(root, "input", 64, securefile.TrustFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "inside" {
		t.Fatalf("catalog root read = %q, want inside", raw)
	}
}

func TestAgentCatalogArchiveHonorsRemainingUncompressedBudget(t *testing.T) {
	fixture := newAgentCatalogCLIFixture(t)
	archivePath := filepath.Join(fixture.releaseFixture.directory, "expansion.tar.gz")
	archiveRaw := writeAgentCatalogExpansionArchive(t, archivePath)
	releaseRaw, err := os.ReadFile(fixture.releaseFixture.outputPath)
	if err != nil {
		t.Fatal(err)
	}
	publisherPublic, err := readPublicKey(fixture.releaseFixture.publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := agentrelease.Verify(
		releaseRaw,
		map[string]ed25519.PublicKey{"publisher-a": publisherPublic},
		fixture.releaseFixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	release := verified.Release
	release.ReleaseID = "compressed-expansion"
	release.Archive.SHA256Digest = dsse.Digest(archiveRaw)
	release.Archive.SizeBytes = int64(len(archiveRaw))
	publisherPrivate, err := readPrivateKey(fixture.releaseFixture.privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	signedRelease, err := agentrelease.Sign(
		release,
		"publisher-a",
		publisherPrivate,
		fixture.releaseFixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	releasePath := filepath.Join(
		fixture.releaseFixture.directory,
		"compressed-expansion.release.dsse.json",
	)
	if err := os.WriteFile(releasePath, signedRelease, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.source.Entries = []agentCatalogSourceEntry{{
		EntryID:               "compressed-expansion",
		Status:                agentcatalog.StatusCandidate,
		Release:               filepath.Base(releasePath),
		PublisherKeyID:        "publisher-a",
		PublisherPublicKey:    filepath.Base(fixture.releaseFixture.publicKeyPath),
		Archive:               filepath.Base(archivePath),
		SkillManifest:         filepath.Base(fixture.releaseFixture.skillManifestPath),
		QualificationEvidence: filepath.Base(fixture.releaseFixture.qualificationEvidencePath),
	}}
	fixture.writeSource(t)
	root, _, err := openAgentCatalogInputRoot(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	preflight, err := preflightAgentCatalogEntries(
		root,
		fixture.source.Entries,
		fixture.releaseFixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	remaining := max(int64(64<<10), int64(len(archiveRaw)))
	if _, _, err := buildAgentCatalogEntry(root, preflight[0], remaining); err == nil ||
		!strings.Contains(err.Error(), "uncompressed byte limit") {
		t.Fatalf("remaining uncompressed budget err = %v", err)
	}
}

func TestAgentCatalogIdentifiersRequireLeadingAlphaNumericBeforeInputIO(t *testing.T) {
	t.Run("curator key ID", func(t *testing.T) {
		err := run([]string{
			"agent-catalog", "issue",
			"-manifest", "missing-manifest.json",
			"-key", "missing-key",
			"-key-id", "-curator",
			"-out", "unused",
		}, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "curator key ID is invalid") ||
			strings.Contains(err.Error(), "read agent catalog source") {
			t.Fatalf("leading punctuation key ID err = %v", err)
		}
	})

	t.Run("entry ID", func(t *testing.T) {
		fixture := newAgentCatalogCLIFixture(t)
		fixture.source.Entries[0].EntryID = ".hermes"
		fixture.source.Entries[0].Release = "missing-release.dsse.json"
		fixture.writeSource(t)
		err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil ||
			!strings.Contains(err.Error(), "entry identity or status is invalid") ||
			strings.Contains(err.Error(), "read agent release") {
			t.Fatalf("leading punctuation entry ID err = %v", err)
		}
	})
}

func TestAgentCatalogCapabilitySearchCannotBeSpoofedByPublisherText(t *testing.T) {
	fixture := newAgentCatalogCLIFixture(t)
	if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	verified, err := loadVerifiedAgentCatalog(agentCatalogReadOptions{
		inputPath: fixture.catalogPath, publicKeyPath: fixture.curatorPublic, keyID: "curator-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := range verified.Entries {
		if verified.Entries[index].Entry.EntryID != "hermes-primary" {
			continue
		}
		if verified.Entries[index].Release.Capsule.Capabilities.Inference {
			t.Fatal("spoofing fixture unexpectedly grants inference")
		}
		verified.Entries[index].Release.Release.Display.Summary =
			"Publisher text says capability:inference despite the verified capsule."
		verified.Entries[index].Release.Release.Qualification.Limitations = append(
			verified.Entries[index].Release.Release.Qualification.Limitations,
			"capability:inference",
		)
	}
	filtered := filterAgentCatalogEntries(verified.Entries, "", "CAPABILITY:INFERENCE")
	if len(filtered) != 1 || filtered[0].Entry.EntryID != "hermes-next" {
		t.Fatalf("structural capability search was spoofed by publisher text: %#v", filtered)
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
	secondCapsule.Command = []string{"serve", "--candidate", "line one\nline two"}
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

func writeAgentCatalogExpansionArchive(t *testing.T, path string) []byte {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	const expandedBytes = 1 << 20
	if err := tarWriter.WriteHeader(&tar.Header{
		Name: "blobs/sha256/" + strings.Repeat("0", 64),
		Mode: 0o600,
		Size: expandedBytes,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(bytes.Repeat([]byte{0}, expandedBytes)); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
