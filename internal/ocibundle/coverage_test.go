package ocibundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONHelpersRejectMalformedDuplicateAndCanceledInput(t *testing.T) {
	type document struct {
		A int `json:"a"`
	}

	var decoded document
	if err := decodeStrictJSONContext(
		context.Background(), []byte(`{"a":1}`), &decoded,
	); err != nil || decoded.A != 1 {
		t.Fatalf("strict decode = %#v err=%v", decoded, err)
	}
	tests := []struct {
		name string
		raw  []byte
		run  func(context.Context, []byte) error
		want string
	}{
		{
			name: "strict unknown field",
			raw:  []byte(`{"a":1,"b":2}`),
			run: func(ctx context.Context, raw []byte) error {
				return decodeStrictJSONContext(ctx, raw, &document{})
			},
			want: "unknown field",
		},
		{
			name: "strict extra value",
			raw:  []byte(`{"a":1} {}`),
			run: func(ctx context.Context, raw []byte) error {
				return decodeStrictJSONContext(ctx, raw, &document{})
			},
			want: "trailing data",
		},
		{
			name: "plain malformed",
			raw:  []byte(`{"a":`),
			run: func(ctx context.Context, raw []byte) error {
				return decodeJSONContext(ctx, raw, &document{})
			},
			want: "unexpected EOF",
		},
		{
			name: "plain extra value",
			raw:  []byte(`{"a":1} []`),
			run: func(ctx context.Context, raw []byte) error {
				return decodeJSONContext(ctx, raw, &document{})
			},
			want: "exactly one value",
		},
		{
			name: "invalid utf8",
			raw:  []byte{0xff},
			run:  rejectDuplicateJSONContext,
			want: "valid UTF-8",
		},
		{
			name: "nested duplicate",
			raw:  []byte(`{"outer":[{"x":1,"x":2}]}`),
			run:  rejectDuplicateJSONContext,
			want: "duplicate JSON member",
		},
		{
			name: "duplicate trailing value",
			raw:  []byte(`{"a":1} true`),
			run:  rejectDuplicateJSONContext,
			want: "trailing data",
		},
		{
			name: "unterminated object",
			raw:  []byte(`{"a":1`),
			run:  rejectDuplicateJSONContext,
			want: "not terminated",
		},
		{
			name: "unterminated array",
			raw:  []byte(`[1,2`),
			run:  rejectDuplicateJSONContext,
			want: "not terminated",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run(context.Background(), test.raw)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
		})
	}

	if err := rejectDuplicateJSONContext(
		context.Background(), []byte(`{"a":[1,{"b":true}],"c":null}`),
	); err != nil {
		t.Fatalf("valid nested JSON: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, run := range map[string]func() error{
		"strict": func() error {
			return decodeStrictJSONContext(canceled, []byte(`{"a":1}`), &document{})
		},
		"plain": func() error {
			return decodeJSONContext(canceled, []byte(`{"a":1}`), &document{})
		},
		"duplicates": func() error {
			return rejectDuplicateJSONContext(canceled, []byte(`{"a":1}`))
		},
	} {
		t.Run("canceled "+name, func(t *testing.T) {
			if err := run(); !errors.Is(err, context.Canceled) {
				t.Fatalf("err=%v, want canceled", err)
			}
		})
	}
}

func TestContextAdaptersAndSmallHelpers(t *testing.T) {
	//nolint:staticcheck // This adversarial case verifies the explicit nil-context guard.
	if err := contextError(nil); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil context err=%v", err)
	}
	readerContext := &cancelOnErrCallContext{
		Context: context.Background(), cancelAt: 2,
	}
	buffer := make([]byte, 3)
	count, err := (contextReader{
		ctx: readerContext, reader: strings.NewReader("abc"),
	}).Read(buffer)
	if count != 3 || !errors.Is(err, context.Canceled) {
		t.Fatalf("reader count=%d err=%v", count, err)
	}
	writerContext := &cancelOnErrCallContext{
		Context: context.Background(), cancelAt: 2,
	}
	var output bytes.Buffer
	count, err = (contextWriter{
		ctx: writerContext, writer: &output,
	}).Write([]byte("abc"))
	if count != 3 || !errors.Is(err, context.Canceled) ||
		output.String() != "abc" {
		t.Fatalf("writer count=%d err=%v output=%q", count, err, output.String())
	}

	if zero, err := allZeroContext(
		context.Background(), make([]byte, 8193),
	); err != nil || !zero {
		t.Fatalf("all zero=%v err=%v", zero, err)
	}
	if zero, err := allZeroContext(
		context.Background(), []byte{0, 1, 0},
	); err != nil || zero {
		t.Fatalf("nonzero=%v err=%v", zero, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := allZeroContext(canceled, []byte{0}); !errors.Is(err, context.Canceled) {
		t.Fatalf("all-zero canceled err=%v", err)
	}
	primary := errors.New("primary")
	fallback := errors.New("fallback")
	if nonNil(primary, fallback) != primary || nonNil(nil, fallback) != fallback {
		t.Fatal("nonNil did not preserve primary/fallback semantics")
	}
	if lowerHex("0123abcdef") != true || lowerHex("ABC") != false ||
		lowerHex("g") != false {
		t.Fatal("lowerHex accepted an invalid digest suffix")
	}
}

func TestDockerManifestValidationRejectsEveryAmbiguousShape(t *testing.T) {
	config := descriptor{
		Digest: "sha256:" + strings.Repeat("a", 64),
	}
	layers := []descriptor{{
		Digest: "sha256:" + strings.Repeat("b", 64),
	}}
	valid := []dockerManifestEntry{{
		Config: blobPath(config.Digest),
		Layers: []string{blobPath(layers[0].Digest)},
		RepoTags: []string{
			"registry.example/agent:approved",
		},
	}}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	tags, err := validateDockerManifestContext(
		context.Background(), raw, config, layers,
	)
	if err != nil || len(tags) != 1 || tags[0] != valid[0].RepoTags[0] {
		t.Fatalf("tags=%v err=%v", tags, err)
	}

	tooManyTags := make([]string, 65)
	for index := range tooManyTags {
		tooManyTags[index] = "tag-" + strings.Repeat("x", index+1)
	}
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "duplicate JSON",
			raw:  []byte(`[{"Config":"x","Config":"y","Layers":[]}]`),
			want: "strict JSON",
		},
		{name: "malformed", raw: []byte(`[`), want: "strict JSON"},
		{name: "empty", raw: []byte(`[]`), want: "exactly one image"},
		{name: "multiple", raw: []byte(`[{},{}]`), want: "exactly one image"},
		{
			name: "config mismatch",
			raw: mustJSON(t, []dockerManifestEntry{{
				Config: "wrong", Layers: valid[0].Layers,
			}}),
			want: "disagrees",
		},
		{
			name: "layer count",
			raw: mustJSON(t, []dockerManifestEntry{{
				Config: valid[0].Config, Layers: nil,
			}}),
			want: "disagrees",
		},
		{
			name: "layer order",
			raw: mustJSON(t, []dockerManifestEntry{{
				Config: valid[0].Config, Layers: []string{"wrong"},
			}}),
			want: "layer order",
		},
		{
			name: "too many tags",
			raw: mustJSON(t, []dockerManifestEntry{{
				Config: valid[0].Config, Layers: valid[0].Layers,
				RepoTags: tooManyTags,
			}}),
			want: "too many",
		},
		{
			name: "invalid empty tag",
			raw: mustJSON(t, []dockerManifestEntry{{
				Config: valid[0].Config, Layers: valid[0].Layers,
				RepoTags: []string{""},
			}}),
			want: "invalid repository tag",
		},
		{
			name: "invalid newline tag",
			raw: mustJSON(t, []dockerManifestEntry{{
				Config: valid[0].Config, Layers: valid[0].Layers,
				RepoTags: []string{"bad\nvalue"},
			}}),
			want: "invalid repository tag",
		},
		{
			name: "duplicate tag",
			raw: mustJSON(t, []dockerManifestEntry{{
				Config: valid[0].Config, Layers: valid[0].Layers,
				RepoTags: []string{"same", "same"},
			}}),
			want: "duplicate repository tag",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateDockerManifestContext(
				context.Background(), test.raw, config, layers,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := validateDockerManifestContext(
		canceled, raw, config, layers,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled manifest err=%v", err)
	}
}

func TestScanArchiveRejectsStructuralAndTrailerFailures(t *testing.T) {
	blob := []byte("verified blob")
	blobName := blobPath(testDigest(blob))
	validEntries := []rawTarEntry{
		{name: "blobs", kind: tar.TypeDir},
		{name: "blobs/sha256", kind: tar.TypeDir},
		{name: "oci-layout", data: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{name: "index.json", data: []byte(`{}`)},
		{name: blobName, data: blob},
	}
	valid := writeRawTar(t, validEntries, nil)
	scan, err := scanArchiveContext(context.Background(), valid, DefaultLimits())
	if err != nil || len(scan.blobs) != 1 || len(scan.layout) == 0 ||
		len(scan.index) == 0 {
		t.Fatalf("scan=%#v err=%v", scan, err)
	}

	tests := []struct {
		name    string
		entries []rawTarEntry
		trailer []byte
		limits  func(Limits) Limits
		want    string
	}{
		{
			name: "duplicate path",
			entries: []rawTarEntry{
				{name: "oci-layout", data: []byte("a")},
				{name: "oci-layout", data: []byte("b")},
			},
			want: "duplicate path",
		},
		{
			name:    "unexpected directory",
			entries: []rawTarEntry{{name: "other", kind: tar.TypeDir}},
			want:    "unexpected directory",
		},
		{
			name: "nonregular",
			entries: []rawTarEntry{{
				name: "link", kind: tar.TypeSymlink, link: "index.json",
			}},
			want: "not a regular file",
		},
		{
			name:    "unexpected blob path",
			entries: []rawTarEntry{{name: "blobs/not-sha256/value", data: blob}},
			want:    "unexpected path",
		},
		{
			name:    "uppercase blob path",
			entries: []rawTarEntry{{name: "blobs/sha256/" + strings.Repeat("A", 64), data: blob}},
			want:    "unexpected path",
		},
		{
			name:    "blob digest mismatch",
			entries: []rawTarEntry{{name: blobPath("sha256:" + strings.Repeat("a", 64)), data: blob}},
			want:    "digest mismatch",
		},
		{
			name: "metadata limit",
			entries: []rawTarEntry{{
				name: "oci-layout", data: []byte("12345"),
			}},
			limits: func(limits Limits) Limits {
				limits.MaxMetadataBytes = 4
				return limits
			},
			want: "exceeds 4 bytes",
		},
		{
			name: "uncompressed limit",
			entries: []rawTarEntry{{
				name: "oci-layout", data: bytes.Repeat([]byte("x"), 513),
			}},
			limits: func(limits Limits) Limits {
				limits.MaxUncompressedBytes = 512
				return limits
			},
			want: "uncompressed byte limit",
		},
		{
			name:    "missing required content",
			entries: []rawTarEntry{{name: "oci-layout", data: []byte("x")}},
			want:    "missing layout, index, or blobs",
		},
		{
			name:    "nonzero trailer",
			entries: validEntries,
			trailer: []byte{1},
			want:    "trailing data",
		},
		{
			name:    "excessive trailer",
			entries: validEntries,
			trailer: make([]byte, maxTrailingZeroBytes+1),
			want:    "trailing data",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultLimits()
			if test.limits != nil {
				limits = test.limits(limits)
			}
			path := writeRawTar(t, test.entries, test.trailer)
			_, err := scanArchiveContext(context.Background(), path, limits)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
		})
	}

	truncatedMetadata := writeTruncatedTar(
		t, "oci-layout", 16, []byte("short"),
	)
	if _, err := scanArchiveContext(
		context.Background(), truncatedMetadata, DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "read OCI metadata") {
		t.Fatalf("truncated metadata err=%v", err)
	}
	truncatedBlob := writeTruncatedTar(
		t, blobName, int64(len(blob)+10), blob,
	)
	if _, err := scanArchiveContext(
		context.Background(), truncatedBlob, DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "hash OCI blob") {
		t.Fatalf("truncated blob err=%v", err)
	}
	corruptHeader := filepath.Join(t.TempDir(), "corrupt.tar")
	if err := os.WriteFile(
		corruptHeader, bytes.Repeat([]byte{0xff}, 1024), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := scanArchiveContext(
		context.Background(), corruptHeader, DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "tar header") {
		t.Fatalf("corrupt tar err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanArchiveContext(
		canceled, valid, DefaultLimits(),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scan err=%v", err)
	}
}

func TestReadBlobContextRejectsMutationAndMalformedArchives(t *testing.T) {
	content := []byte("metadata")
	digest := testDigest(content)
	name := blobPath(digest)
	valid := writeRawTar(t, []rawTarEntry{
		{name: "unrelated", data: []byte("skip")},
		{name: name, data: content},
	}, nil)
	raw, err := readBlobContext(
		context.Background(), valid, digest, int64(len(content)),
		DefaultLimits(),
	)
	if err != nil || !bytes.Equal(raw, content) {
		t.Fatalf("blob=%q err=%v", raw, err)
	}

	tests := []struct {
		name   string
		path   string
		digest string
		size   int64
		want   string
	}{
		{
			name: "invalid digest", path: valid, digest: "bad",
			size: int64(len(content)), want: "invalid or excessive",
		},
		{
			name: "invalid size", path: valid, digest: digest,
			size: 0, want: "invalid or excessive",
		},
		{
			name: "missing archive", path: filepath.Join(t.TempDir(), "missing"),
			digest: digest, size: int64(len(content)), want: "open OCI archive",
		},
		{
			name: "missing blob",
			path: writeRawTar(t, []rawTarEntry{{
				name: "other", data: []byte("value"),
			}}, nil),
			digest: digest, size: int64(len(content)), want: "missing metadata blob",
		},
		{
			name: "size changed", path: valid, digest: digest,
			size: int64(len(content) + 1), want: "changed between",
		},
		{
			name: "type changed",
			path: writeRawTar(t, []rawTarEntry{{
				name: name, kind: tar.TypeSymlink, link: "other",
			}}, nil),
			digest: digest, size: int64(len(content)), want: "changed between",
		},
		{
			name: "digest changed",
			path: writeRawTar(t, []rawTarEntry{{
				name: name, data: []byte("different"),
			}}, nil),
			digest: digest, size: int64(len("different")), want: "changed between",
		},
		{
			name: "truncated blob",
			path: writeTruncatedTar(
				t, name, int64(len(content)+10), content,
			),
			digest: digest, size: int64(len(content) + 10),
			want: "read OCI metadata blob",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := readBlobContext(
				context.Background(), test.path, test.digest, test.size,
				DefaultLimits(),
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readBlobContext(
		canceled, valid, digest, int64(len(content)), DefaultLimits(),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled blob read err=%v", err)
	}
	corruptHeader := filepath.Join(t.TempDir(), "corrupt.tar")
	if err := os.WriteFile(
		corruptHeader, bytes.Repeat([]byte{0xff}, 1024), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := readBlobContext(
		context.Background(), corruptHeader, digest, int64(len(content)),
		DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "tar header") {
		t.Fatalf("corrupt blob tar err=%v", err)
	}
}

func TestOpenArchiveContextRejectsShortAndInvalidGzip(t *testing.T) {
	short := filepath.Join(t.TempDir(), "short.tar")
	if err := os.WriteFile(short, []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openArchiveContext(
		context.Background(), short, DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "archive header") {
		t.Fatalf("short archive err=%v", err)
	}
	invalidGzip := filepath.Join(t.TempDir(), "invalid.tar.gz")
	if err := os.WriteFile(
		invalidGzip, []byte{0x1f, 0x8b, 0, 1, 2, 3}, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openArchiveContext(
		context.Background(), invalidGzip, DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "open gzip") {
		t.Fatalf("invalid gzip err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := openArchiveContext(
		canceled, short, DefaultLimits(),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open err=%v", err)
	}

	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	gzipPath := filepath.Join(t.TempDir(), "valid.gz")
	if err := os.WriteFile(gzipPath, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, closeReader, err := openArchiveContext(
		context.Background(), gzipPath, DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "payload" {
		t.Fatalf("gzip payload=%q err=%v", got, err)
	}
	if err := closeReader(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectAndVerifyRejectAdditionalContractDrift(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{})
	//nolint:staticcheck // This adversarial case verifies the explicit nil-context guard.
	if _, err := InspectContext(nil, archive, DefaultLimits()); err == nil ||
		!strings.Contains(err.Error(), "context is required") {
		t.Fatalf("nil inspect context err=%v", err)
	}
	if _, err := InspectContext(
		context.Background(), filepath.Join(t.TempDir(), "missing"),
		DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "stat OCI archive") {
		t.Fatalf("missing inspect err=%v", err)
	}
	if _, err := InspectContext(
		context.Background(), archive, Limits{},
	); err == nil || !strings.Contains(err.Error(), "limits") {
		t.Fatalf("invalid limits err=%v", err)
	}
	if _, err := VerifyContext(
		context.Background(), archive, Identity{}, DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "expected image identity") {
		t.Fatalf("invalid expected identity err=%v", err)
	}

	for name, platform := range map[string]Platform{
		"empty os":           {Architecture: "amd64"},
		"empty architecture": {OS: "linux"},
		"slash":              {OS: "linux/host", Architecture: "amd64"},
		"long variant": {
			OS: "linux", Architecture: "amd64", Variant: strings.Repeat("x", 33),
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := identity
			value.Platform = platform
			if err := value.validate(); err == nil ||
				!strings.Contains(err.Error(), "platform") {
				t.Fatalf("identity validation err=%v", err)
			}
		})
	}

	canceledAfterStat := &cancelOnErrCallContext{
		Context: context.Background(), cancelAt: 2,
	}
	if _, err := InspectContext(
		canceledAfterStat, archive, DefaultLimits(),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel after stat err=%v", err)
	}
}

func TestSnapshotDetectsReplacementAndPostCopyMutation(t *testing.T) {
	archive, _ := testArchive(t, archiveOptions{})
	parent := t.TempDir()
	replacementContext := &actionOnErrCallContext{
		Context: context.Background(),
		call:    2,
		action: func() {
			old := archive + ".old"
			if err := os.Rename(archive, old); err != nil {
				t.Fatalf("rename source: %v", err)
			}
			if err := os.WriteFile(archive, []byte("replacement"), 0o600); err != nil {
				t.Fatalf("replace source: %v", err)
			}
		},
	}
	replacementSnapshot := filepath.Join(parent, "replacement.snapshot")
	if _, err := snapshotArchiveIdentityContext(
		replacementContext, archive, replacementSnapshot, DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "changed while it was opened") {
		t.Fatalf("replacement err=%v", err)
	}
	if _, err := os.Stat(replacementSnapshot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement snapshot retained: %v", err)
	}

	archive, _ = testArchive(t, archiveOptions{})
	mutationSnapshot := filepath.Join(parent, "mutation.snapshot")
	mutationContext := &snapshotMutationContext{
		Context:      context.Background(),
		sourcePath:   archive,
		snapshotPath: mutationSnapshot,
	}
	if _, err := snapshotArchiveIdentityContext(
		mutationContext, archive, mutationSnapshot, DefaultLimits(),
	); err == nil || !strings.Contains(err.Error(), "changed while it was snapshotted") {
		t.Fatalf("post-copy mutation err=%v", err)
	}
	if _, err := os.Stat(mutationSnapshot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mutation snapshot retained: %v", err)
	}
}

func TestInspectSourceAndPrepareCleanupAtLateCancellation(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{})
	privateTemp := t.TempDir()
	t.Setenv("TMPDIR", privateTemp)

	inspectContext := &cancelAfterTempCleanupContext{
		Context: context.Background(),
		root:    privateTemp,
		pattern: ".steward-oci-inspect-*",
	}
	if _, err := InspectSourceContext(
		inspectContext, archive, DefaultLimits(),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("inspect cleanup cancellation err=%v", err)
	}
	assertDirectoryEmpty(t, privateTemp)

	prepareContext := &cancelAfterTempCleanupContext{
		Context: context.Background(),
		root:    privateTemp,
		pattern: ".steward-oci-*",
	}
	if _, err := PrepareContext(
		prepareContext, archive, identity, DefaultLimits(),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("prepare cleanup cancellation err=%v", err)
	}
	assertDirectoryEmpty(t, privateTemp)

	sealContext := &cancelWhenLoadSealedContext{
		Context: context.Background(),
		root:    privateTemp,
	}
	if _, err := PrepareContext(
		sealContext, archive, identity, DefaultLimits(),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("prepare seal cancellation err=%v", err)
	}
	assertDirectoryEmpty(t, privateTemp)
}

func TestInspectSourceAndPrepareCleanInvalidSnapshots(t *testing.T) {
	invalid := filepath.Join(t.TempDir(), "invalid.tar")
	if err := os.WriteFile(invalid, []byte("not an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateTemp := t.TempDir()
	t.Setenv("TMPDIR", privateTemp)
	if _, err := InspectSource(invalid, DefaultLimits()); err == nil {
		t.Fatal("invalid source inspection unexpectedly succeeded")
	}
	assertDirectoryEmpty(t, privateTemp)

	_, identity := testArchive(t, archiveOptions{})
	if _, err := Prepare(invalid, identity, DefaultLimits()); err == nil {
		t.Fatal("invalid preparation unexpectedly succeeded")
	}
	assertDirectoryEmpty(t, privateTemp)

	tooLarge := ArchiveIdentity{
		Digest: "sha256:" + strings.Repeat("a", 64),
		Bytes:  DefaultLimits().MaxArchiveBytes + 1,
	}
	if err := tooLarge.validate(DefaultLimits()); err == nil ||
		!strings.Contains(err.Error(), "archive size") {
		t.Fatalf("oversized archive identity err=%v", err)
	}
}

func TestSanitizationDetectsSnapshotReplacementBetweenPasses(t *testing.T) {
	archive, _ := testArchive(t, archiveOptions{})
	image, err := Inspect(archive, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("missing verified blobs", func(t *testing.T) {
		working := copyTestFile(t, archive)
		writer := &replacePathOnFirstWrite{
			path: working,
			replacement: func() []byte {
				return make([]byte, 1024)
			},
		}
		err := writeSanitizedArchive(
			working, writer, image, DefaultLimits(),
		)
		if err == nil || !strings.Contains(err.Error(), "missing a verified blob") {
			t.Fatalf("missing blobs err=%v", err)
		}
	})
	t.Run("changed verified blob header", func(t *testing.T) {
		working := copyTestFile(t, archive)
		writer := &replacePathOnFirstWrite{
			path: working,
			replacement: func() []byte {
				return rawTarBytes(t, []rawTarEntry{{
					name: blobPath(image.ManifestDigest), data: []byte("x"),
				}}, nil)
			},
		}
		err := writeSanitizedArchive(
			working, writer, image, DefaultLimits(),
		)
		if err == nil || !strings.Contains(err.Error(), "changed before sanitization") {
			t.Fatalf("changed blob err=%v", err)
		}
	})
}

func TestSanitizationReportsDataCopyAndCloseFailures(t *testing.T) {
	archive, _ := testArchive(t, archiveOptions{})
	image, err := Inspect(archive, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var successful bytes.Buffer
	if err := writeSanitizedArchive(
		archive, &successful, image, DefaultLimits(),
	); err != nil {
		t.Fatal(err)
	}

	copyFailure := &failAfterBytesWriter{limit: 3*1024 + 512 + 8}
	err = writeSanitizedArchive(
		archive, copyFailure, image, DefaultLimits(),
	)
	if err == nil || !errors.Is(err, errRejectWrite) ||
		!strings.Contains(err.Error(), "copy sanitized OCI blob") {
		t.Fatalf("copy failure err=%v bytes=%d", err, copyFailure.written)
	}

	closeFailure := &failAfterBytesWriter{
		limit: int64(successful.Len() - 512),
	}
	err = writeSanitizedArchive(
		archive, closeFailure, image, DefaultLimits(),
	)
	if err == nil || !errors.Is(err, errRejectWrite) ||
		!strings.Contains(err.Error(), "finish sanitized Docker load archive") {
		t.Fatalf("close failure err=%v bytes=%d", err, closeFailure.written)
	}
}

func TestCancellationAtEverySuccessfulCheckpoint(t *testing.T) {
	archive, identity := testArchive(t, archiveOptions{})
	image, err := Inspect(archive, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	configRaw := []byte(`{"architecture":"amd64","os":"linux"}`)
	configDigest := testDigest(configRaw)
	configArchive := writeRawTar(t, []rawTarEntry{{
		name: blobPath(configDigest), data: configRaw,
	}}, nil)

	assertEveryCheckpointCanceled(t, "inspect", func(ctx context.Context) error {
		_, err := InspectContext(ctx, archive, DefaultLimits())
		return err
	})
	assertEveryCheckpointCanceled(t, "verify", func(ctx context.Context) error {
		_, err := VerifyContext(ctx, archive, identity, DefaultLimits())
		return err
	})
	assertEveryCheckpointCanceled(t, "scan", func(ctx context.Context) error {
		_, err := scanArchiveContext(ctx, archive, DefaultLimits())
		return err
	})
	assertEveryCheckpointCanceled(t, "read blob", func(ctx context.Context) error {
		_, err := readBlobContext(
			ctx, configArchive, configDigest, int64(len(configRaw)),
			DefaultLimits(),
		)
		return err
	})
	assertEveryCheckpointCanceled(t, "snapshot", func(ctx context.Context) error {
		directory := t.TempDir()
		_, err := snapshotArchiveIdentityContext(
			ctx, archive, filepath.Join(directory, "snapshot"),
			DefaultLimits(),
		)
		return err
	})
	assertEveryCheckpointCanceled(t, "sanitize", func(ctx context.Context) error {
		return writeSanitizedArchiveContext(
			ctx, archive, io.Discard, image, DefaultLimits(),
		)
	})

	privateTemp := t.TempDir()
	t.Setenv("TMPDIR", privateTemp)
	assertEveryCheckpointCanceled(t, "inspect source", func(ctx context.Context) error {
		_, err := InspectSourceContext(ctx, archive, DefaultLimits())
		return err
	})
	assertDirectoryEmpty(t, privateTemp)
	assertEveryCheckpointCanceled(t, "prepare", func(ctx context.Context) error {
		prepared, err := PrepareContext(
			ctx, archive, identity, DefaultLimits(),
		)
		if prepared != nil {
			_ = prepared.Close()
		}
		return err
	})
	assertDirectoryEmpty(t, privateTemp)
}

func assertEveryCheckpointCanceled(
	t *testing.T,
	name string,
	run func(context.Context) error,
) {
	t.Helper()
	counter := &cancelOnErrCallContext{
		Context:  context.Background(),
		cancelAt: int(^uint(0) >> 1),
	}
	if err := run(counter); err != nil {
		t.Fatalf("%s baseline: %v", name, err)
	}
	if counter.calls == 0 {
		t.Fatalf("%s did not consult its context", name)
	}
	for cancelAt := 1; cancelAt <= counter.calls; cancelAt++ {
		ctx := &cancelOnErrCallContext{
			Context:  context.Background(),
			cancelAt: cancelAt,
		}
		if err := run(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf(
				"%s cancellation at check %d/%d: %v",
				name, cancelAt, counter.calls, err,
			)
		}
	}
}

type rawTarEntry struct {
	name string
	data []byte
	kind byte
	link string
}

func writeRawTar(
	t *testing.T,
	entries []rawTarEntry,
	trailer []byte,
) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.tar")
	if err := os.WriteFile(path, rawTarBytes(t, entries, trailer), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rawTarBytes(
	t *testing.T,
	entries []rawTarEntry,
	trailer []byte,
) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		size := int64(len(entry.data))
		if kind == tar.TypeDir || kind == tar.TypeSymlink {
			size = 0
		}
		if err := writer.WriteHeader(&tar.Header{
			Name: entry.name, Mode: 0o444, Size: size,
			Typeflag: kind, Linkname: entry.link,
		}); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := writer.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output.Write(trailer)
	return output.Bytes()
}

func writeTruncatedTar(
	t *testing.T,
	name string,
	declaredSize int64,
	content []byte,
) string {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{
		Name: name, Mode: 0o444, Size: declaredSize, Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "truncated.tar")
	if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type cancelOnErrCallContext struct {
	context.Context
	calls    int
	cancelAt int
}

func (ctx *cancelOnErrCallContext) Err() error {
	ctx.calls++
	if ctx.calls >= ctx.cancelAt {
		return context.Canceled
	}
	return ctx.Context.Err()
}

type actionOnErrCallContext struct {
	context.Context
	calls  int
	call   int
	action func()
}

func (ctx *actionOnErrCallContext) Err() error {
	ctx.calls++
	if ctx.calls == ctx.call {
		ctx.action()
	}
	return ctx.Context.Err()
}

type snapshotMutationContext struct {
	context.Context
	sourcePath   string
	snapshotPath string
	mutated      bool
}

func (ctx *snapshotMutationContext) Err() error {
	if !ctx.mutated {
		if info, err := os.Stat(ctx.snapshotPath); err == nil && info.Size() > 0 {
			ctx.mutated = true
			_ = os.Chmod(ctx.sourcePath, 0o620)
		}
	}
	return ctx.Context.Err()
}

type cancelAfterTempCleanupContext struct {
	context.Context
	root    string
	pattern string
	seen    bool
}

func (ctx *cancelAfterTempCleanupContext) Err() error {
	matches, _ := filepath.Glob(filepath.Join(ctx.root, ctx.pattern))
	if len(matches) > 0 {
		ctx.seen = true
	} else if ctx.seen {
		return context.Canceled
	}
	return ctx.Context.Err()
}

type cancelWhenLoadSealedContext struct {
	context.Context
	root string
}

func (ctx *cancelWhenLoadSealedContext) Err() error {
	matches, _ := filepath.Glob(
		filepath.Join(ctx.root, ".steward-oci-*", "docker-load.tar"),
	)
	for _, match := range matches {
		info, err := os.Stat(match)
		if err == nil && info.Mode().Perm() == 0o400 {
			return context.Canceled
		}
	}
	return ctx.Context.Err()
}

func assertDirectoryEmpty(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary directory retained artifacts: %v", entries)
	}
}

func copyTestFile(t *testing.T, source string) string {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "copy.tar")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type replacePathOnFirstWrite struct {
	bytes.Buffer
	path        string
	replacement func() []byte
	replaced    bool
}

func (writer *replacePathOnFirstWrite) Write(raw []byte) (int, error) {
	if !writer.replaced {
		writer.replaced = true
		old := writer.path + ".verified"
		if err := os.Rename(writer.path, old); err != nil {
			return 0, err
		}
		if err := os.WriteFile(
			writer.path, writer.replacement(), 0o600,
		); err != nil {
			return 0, err
		}
	}
	return writer.Buffer.Write(raw)
}

type failAfterBytesWriter struct {
	limit   int64
	written int64
}

func (writer *failAfterBytesWriter) Write(raw []byte) (int, error) {
	remaining := writer.limit - writer.written
	if remaining <= 0 {
		return 0, errRejectWrite
	}
	if int64(len(raw)) <= remaining {
		writer.written += int64(len(raw))
		return len(raw), nil
	}
	writer.written += remaining
	return int(remaining), errRejectWrite
}
