package ocibundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestInspectAndVerifySinglePlatformArchive(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{})
	image, err := Inspect(archive, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if image.Identity != identity || image.BlobCount != 3 || image.BlobBytes == 0 || len(image.LayerDigests) != 1 ||
		len(image.RepoTags) != 1 || image.RepoTags[0] != "registry.example/agent:approved" {
		t.Fatalf("image = %#v, want identity %#v", image, identity)
	}
	if _, err := Verify(archive, identity, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	wrong := identity
	wrong.Platform.Architecture = "arm64"
	if _, err := Verify(archive, wrong, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched signed identity err = %v", err)
	}
}

func TestInspectAcceptsGzipAndRejectsDeclaredVolumes(t *testing.T) {
	gzipArchive, _ := testArchive(t, archiveOptions{gzip: true})
	if _, err := Inspect(gzipArchive, DefaultLimits()); err != nil {
		t.Fatalf("gzip archive: %v", err)
	}
	ociArchive, identity := testArchive(t, archiveOptions{omitDockerManifest: true})
	image, err := Inspect(ociArchive, DefaultLimits())
	if err != nil {
		t.Fatalf("pure OCI archive: %v", err)
	}
	if image.Identity != identity || len(image.RepoTags) != 0 {
		t.Fatalf("pure OCI image = %#v", image)
	}
	volumeArchive, _ := testArchive(t, archiveOptions{volumes: true})
	if _, err := Inspect(volumeArchive, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "writable volumes") {
		t.Fatalf("declared volume err = %v", err)
	}
}

func TestInspectRejectsUnsafeOrAmbiguousArchives(t *testing.T) {
	tests := []struct {
		name    string
		options archiveOptions
		want    string
	}{
		{"bad blob digest", archiveOptions{corruptLayer: true}, "digest mismatch"},
		{"duplicate JSON", archiveOptions{duplicateConfigKey: true}, "strict JSON"},
		{"ambiguous index", archiveOptions{twoManifests: true}, "one unambiguous"},
		{"link entry", archiveOptions{linkEntry: true}, "not a regular file"},
		{"unsafe path", archiveOptions{unsafePath: true}, "unsafe path"},
		{"descriptor size", archiveOptions{wrongLayerSize: true}, "size mismatch"},
		{"Docker manifest disagreement", archiveOptions{wrongDockerLayer: true}, "disagrees"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive, _ := testArchive(t, test.options)
			if _, err := Inspect(archive, DefaultLimits()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestInspectRejectsWritableAndBoundedMedia(t *testing.T) {
	archive, _ := testArchive(t, archiveOptions{})
	if err := os.Chmod(archive, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(archive, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "write permission") {
		t.Fatalf("writable archive err = %v", err)
	}
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxArchiveBytes = 8
	limits.MaxUncompressedBytes = 8
	if _, err := Inspect(archive, limits); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversized archive err = %v", err)
	}
	limits = DefaultLimits()
	limits.MaxEntries = 1
	if _, err := Inspect(archive, limits); err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("entry cap err = %v", err)
	}
}

func TestExternalDockerSaveArchive(t *testing.T) {
	archive := os.Getenv("STEWARD_TEST_OCI_ARCHIVE")
	if archive == "" {
		t.Skip("set STEWARD_TEST_OCI_ARCHIVE to exercise a real Docker save archive")
	}
	image, err := Inspect(archive, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if image.ManifestDigest == "" || image.ConfigDigest == "" || image.Platform.OS != "linux" {
		t.Fatalf("unexpected real archive identity: %#v", image)
	}
	prepared, err := Prepare(archive, image.Identity, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	reader, err := prepared.Reader()
	if err != nil {
		t.Fatal(err)
	}
	sanitized := filepath.Join(t.TempDir(), "docker-load.tar")
	file, err := os.OpenFile(sanitized, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(file, reader); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Verify(sanitized, image.Identity, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.RepoTags) != 0 || loaded.BlobCount != referencedBlobCount(image) {
		t.Fatalf("prepared real archive was not minimal and tag-free: %#v", loaded)
	}
}

type archiveOptions struct {
	gzip, volumes, corruptLayer, duplicateConfigKey, twoManifests bool
	linkEntry, unsafePath, wrongLayerSize, wrongDockerLayer       bool
	extraBlob, repositories                                       bool
	omitDockerManifest                                            bool
}

func testArchive(t *testing.T, options archiveOptions) (string, Identity) {
	t.Helper()
	layer := []byte("one verified uncompressed layer")
	layerDigest := testDigest(layer)
	configObject := map[string]any{
		"architecture": "amd64", "os": "linux", "variant": "v1",
		"config": map[string]any{"Env": []string{"PATH=/bin"}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{layerDigest}},
	}
	if options.volumes {
		configObject["config"].(map[string]any)["Volumes"] = map[string]any{"/escape": map[string]any{}}
	}
	config, _ := json.Marshal(configObject)
	if options.duplicateConfigKey {
		config = []byte(`{"architecture":"amd64","architecture":"arm64","os":"linux","variant":"v1","config":{},"rootfs":{"type":"layers","diff_ids":[]}}`)
	}
	configDigest := testDigest(config)
	layerSize := len(layer)
	if options.wrongLayerSize {
		layerSize++
	}
	manifestObject := map[string]any{
		"schemaVersion": 2, "mediaType": ociManifestMediaType,
		"config": map[string]any{"mediaType": ociConfigMediaType, "digest": configDigest, "size": len(config)},
		"layers": []any{map[string]any{"mediaType": ociLayerMediaType, "digest": layerDigest, "size": layerSize}},
	}
	manifest, _ := json.Marshal(manifestObject)
	manifestDigest := testDigest(manifest)
	descriptor := map[string]any{
		"mediaType": ociManifestMediaType, "digest": manifestDigest, "size": len(manifest),
		"platform": map[string]any{"os": "linux", "architecture": "amd64", "variant": "v1"},
	}
	manifests := []any{descriptor}
	if options.twoManifests {
		manifests = append(manifests, descriptor)
	}
	index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ociIndexMediaType, "manifests": manifests})
	dockerLayer := "blobs/sha256/" + strings.TrimPrefix(layerDigest, "sha256:")
	if options.wrongDockerLayer {
		dockerLayer = "blobs/sha256/" + strings.Repeat("f", 64)
	}
	dockerManifest, _ := json.Marshal([]any{map[string]any{
		"Config":   "blobs/sha256/" + strings.TrimPrefix(configDigest, "sha256:"),
		"RepoTags": []string{"registry.example/agent:approved"}, "Layers": []string{dockerLayer},
	}})
	entries := map[string][]byte{
		"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": index, "manifest.json": dockerManifest,
		"blobs/sha256/" + strings.TrimPrefix(manifestDigest, "sha256:"): manifest,
		"blobs/sha256/" + strings.TrimPrefix(configDigest, "sha256:"):   config,
		"blobs/sha256/" + strings.TrimPrefix(layerDigest, "sha256:"):    layer,
	}
	if options.omitDockerManifest {
		delete(entries, "manifest.json")
	}
	if options.extraBlob {
		extra := []byte("unreferenced attacker-controlled blob")
		entries["blobs/sha256/"+strings.TrimPrefix(testDigest(extra), "sha256:")] = extra
	}
	if options.repositories {
		entries["repositories"] = []byte(`{"attacker":{"latest":"polluting-tag"}}`)
	}
	if options.corruptLayer {
		entries["blobs/sha256/"+strings.TrimPrefix(layerDigest, "sha256:")] = append(layer, 'x')
	}
	if options.unsafePath {
		entries["../escape"] = []byte("bad")
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	archive := filepath.Join(t.TempDir(), "image.tar")
	file, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var writer *tar.Writer
	var gzipWriter *gzip.Writer
	if options.gzip {
		gzipWriter = gzip.NewWriter(file)
		writer = tar.NewWriter(gzipWriter)
	} else {
		writer = tar.NewWriter(file)
	}
	for _, name := range names {
		raw := entries[name]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o444, Size: int64(len(raw)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if options.linkEntry {
		if err := writer.WriteHeader(&tar.Header{Name: "link", Linkname: "index.json", Typeflag: tar.TypeSymlink}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if gzipWriter != nil {
		if err := gzipWriter.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return archive, Identity{
		ManifestDigest: manifestDigest, ConfigDigest: configDigest,
		Platform: Platform{OS: "linux", Architecture: "amd64", Variant: "v1"},
	}
}

func testDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
