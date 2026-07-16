package ocibundle

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPrepareSnapshotsAndSanitizesDockerLoadArchive(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{extraBlob: true, repositories: true})
	source, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare(archive, identity, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if prepared.Archive != (ArchiveIdentity{Digest: testDigest(source), Bytes: int64(len(source))}) {
		t.Fatalf("prepared archive identity = %#v", prepared.Archive)
	}
	if len(prepared.Image.RepoTags) != 0 || prepared.Image.BlobCount != 3 {
		t.Fatalf("prepared image metadata = %#v", prepared.Image)
	}
	if _, err := prepared.file.WriteAt([]byte("mutation"), 0); err == nil {
		t.Fatal("prepared Docker load descriptor remained writable")
	}

	// Replacing the user-controlled pathname after preparation cannot alter the
	// already-open, unlinked descriptor handed to Docker.
	if err := os.Rename(archive, archive+".replaced"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, []byte("attacker replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := prepared.Reader()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	entries := readTarEntries(t, raw)
	if _, ok := entries["repositories"]; ok {
		t.Fatal("sanitized archive retained Docker repositories metadata")
	}
	extra := "blobs/sha256/" + strings.TrimPrefix(testDigest([]byte("unreferenced attacker-controlled blob")), "sha256:")
	if _, ok := entries[extra]; ok {
		t.Fatal("sanitized archive retained an unreferenced blob")
	}
	blobCount := 0
	for name := range entries {
		if strings.HasPrefix(name, "blobs/sha256/") {
			blobCount++
		}
	}
	if blobCount != 3 {
		t.Fatalf("sanitized blob count = %d, want manifest, config, and one layer", blobCount)
	}
	var index imageIndex
	if err := json.Unmarshal(entries["index.json"], &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 1 || len(index.Manifests[0].Annotations) != 1 ||
		index.Manifests[0].Annotations["config.digest"] != identity.ConfigDigest {
		t.Fatalf("sanitized index does not bind config identity: %#v", index)
	}
	var manifest []dockerManifestEntry
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 1 || len(manifest[0].RepoTags) != 0 {
		t.Fatalf("sanitized Docker manifest retained tags: %#v", manifest)
	}
	if bytes.Contains(raw, []byte("registry.example/agent:approved")) || bytes.Contains(raw, []byte("polluting-tag")) {
		t.Fatal("sanitized Docker load bytes contain repository tag material")
	}

	// The sanitized result remains a normal single-image Docker/OCI archive and
	// preserves the independently signed identity.
	sanitized := filepath.Join(t.TempDir(), "sanitized.tar")
	if err := os.WriteFile(sanitized, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	image, err := Verify(sanitized, identity, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(image.RepoTags) != 0 || image.BlobCount != 3 {
		t.Fatalf("sanitized image = %#v", image)
	}
}

func TestPrepareBoundRequiresExactSourceBytes(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{})
	source, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	expected := ArchiveIdentity{Digest: testDigest(source), Bytes: int64(len(source))}
	prepared, err := PrepareBound(archive, identity, expected, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Archive != expected {
		t.Fatalf("prepared archive identity = %#v, want %#v", prepared.Archive, expected)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}

	wrongDigest := expected
	wrongDigest.Digest = testDigest([]byte("different archive"))
	if _, err := PrepareBound(archive, identity, wrongDigest, DefaultLimits()); err == nil ||
		!strings.Contains(err.Error(), "signed archive digest and size") {
		t.Fatalf("wrong archive digest err = %v", err)
	}
	wrongSize := expected
	wrongSize.Bytes++
	if _, err := PrepareBound(archive, identity, wrongSize, DefaultLimits()); err == nil ||
		!strings.Contains(err.Error(), "signed archive digest and size") {
		t.Fatalf("wrong archive size err = %v", err)
	}
	if _, err := PrepareBound(archive, identity, ArchiveIdentity{}, DefaultLimits()); err == nil ||
		!strings.Contains(err.Error(), "expected archive identity") {
		t.Fatalf("invalid archive identity err = %v", err)
	}
}

func TestPrepareAcceptsGzipAndReturnsIndependentReaders(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{gzip: true})
	prepared, err := Prepare(archive, identity, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	first, err := prepared.Reader()
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepared.Reader()
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, err := io.ReadAll(first)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := io.ReadAll(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("prepared readers observed different bytes")
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Reader(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("reader after close err = %v", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestPrepareConvertsPureOCIInputToDockerLoadArchive(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{omitDockerManifest: true})
	prepared, err := Prepare(archive, identity, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	reader, err := prepared.Reader()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	entries := readTarEntries(t, raw)
	if len(entries["manifest.json"]) == 0 {
		t.Fatal("prepared pure OCI archive has no Docker compatibility manifest")
	}
}

func TestPrepareRejectsFIFOAndSymlinkBeforeOpening(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{})
	directory := t.TempDir()
	fifo := filepath.Join(directory, "image.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(fifo, identity, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("FIFO preparation err = %v", err)
	}
	symlink := filepath.Join(directory, "image.link")
	if err := os.Symlink(archive, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(symlink, identity, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink preparation err = %v", err)
	}
}

func TestPrepareRejectsUntrustedSourcePermissionsSizeAndIdentity(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{})

	badIdentity := identity
	badIdentity.ManifestDigest = "sha256:not-a-digest"
	if _, err := Prepare(archive, badIdentity, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "expected image identity") {
		t.Fatalf("invalid identity err = %v", err)
	}
	if _, err := Prepare(archive, identity, Limits{}); err == nil || !strings.Contains(err.Error(), "limits") {
		t.Fatalf("invalid limits err = %v", err)
	}
	if _, err := Prepare(filepath.Join(t.TempDir(), "missing.tar"), identity, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "stat OCI archive") {
		t.Fatalf("missing source err = %v", err)
	}

	if err := os.Chmod(archive, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(archive, identity, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "no group/world write") {
		t.Fatalf("writable source err = %v", err)
	}
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatal(err)
	}

	empty := filepath.Join(t.TempDir(), "empty.tar")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(empty, identity, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "between 1") {
		t.Fatalf("empty source err = %v", err)
	}

	info, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxArchiveBytes = info.Size() - 1
	if _, err := Prepare(archive, identity, limits); err == nil || !strings.Contains(err.Error(), "size must be") {
		t.Fatalf("oversized source err = %v", err)
	}
}

func TestSnapshotArchiveProducesPrivateSealedCopy(t *testing.T) {
	archive, _ := testArchive(t, archiveOptions{})
	snapshot := filepath.Join(t.TempDir(), "private", "source.snapshot")
	if err := os.Mkdir(filepath.Dir(snapshot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := snapshotArchive(archive, snapshot, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	sourceRaw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	snapshotRaw, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshotRaw, sourceRaw) {
		t.Fatal("private snapshot does not contain the exact source bytes")
	}
	info, err := os.Stat(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 || !info.Mode().IsRegular() {
		t.Fatalf("snapshot mode = %s, want sealed regular 0400", info.Mode())
	}

	existing := filepath.Join(t.TempDir(), "existing.snapshot")
	if err := os.WriteFile(existing, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshotArchive(archive, existing, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "create private OCI snapshot") {
		t.Fatalf("existing snapshot err = %v", err)
	}
	raw, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "do not replace" {
		t.Fatalf("existing snapshot was replaced: %q", raw)
	}

	missingParent := filepath.Join(t.TempDir(), "missing", "source.snapshot")
	if err := snapshotArchive(archive, missingParent, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "create private OCI snapshot") {
		t.Fatalf("missing destination parent err = %v", err)
	}
}

func TestSanitizationFailsClosedWhenVerifiedContentOrOutputChanges(t *testing.T) {
	archive, _ := testArchive(t, archiveOptions{})
	image, err := Inspect(archive, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	missingManifest := image
	missingManifest.ManifestDigest = "sha256:" + strings.Repeat("f", 64)
	if err := writeSanitizedArchive(archive, io.Discard, missingManifest, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "manifest disappeared") {
		t.Fatalf("missing manifest err = %v", err)
	}

	missingConfig := image
	missingConfig.ConfigDigest = "sha256:" + strings.Repeat("f", 64)
	if err := writeSanitizedArchive(archive, io.Discard, missingConfig, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "blob") {
		t.Fatalf("missing config err = %v", err)
	}

	missingLayer := image
	missingLayer.LayerDigests = []string{"sha256:" + strings.Repeat("f", 64)}
	if err := writeSanitizedArchive(archive, io.Discard, missingLayer, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "blob") {
		t.Fatalf("missing layer err = %v", err)
	}

	if err := writeSanitizedArchive(filepath.Join(t.TempDir(), "missing.tar"), io.Discard, image, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "rescan private OCI snapshot") {
		t.Fatalf("missing snapshot err = %v", err)
	}
	if err := writeSanitizedArchive(archive, rejectingWriter{}, image, DefaultLimits()); err == nil ||
		!strings.Contains(err.Error(), "write sanitized archive header") || !errors.Is(err, errRejectWrite) {
		t.Fatalf("rejected output err = %v", err)
	}
}

func TestPreparedNilAndClosedHandlesFailSafely(t *testing.T) {
	var nilPrepared *Prepared
	if _, err := nilPrepared.Reader(); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil reader err = %v", err)
	}
	if err := nilPrepared.Close(); err != nil {
		t.Fatalf("nil close err = %v", err)
	}
	emptyPrepared := &Prepared{}
	if err := emptyPrepared.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := emptyPrepared.Reader(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed empty reader err = %v", err)
	}
}

var errRejectWrite = errors.New("test sink rejected bytes")

type rejectingWriter struct{}

func (rejectingWriter) Write([]byte) (int, error) { return 0, errRejectWrite }

func readTarEntries(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	entries := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(raw))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = content
	}
	return entries
}
