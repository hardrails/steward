// Package ocibundle verifies the narrow, single-platform Docker/OCI archive
// shape accepted by Steward's offline import workflow. It never extracts files.
package ocibundle

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	DefaultMaxArchiveBytes      = int64(20 << 30)
	DefaultMaxUncompressedBytes = int64(40 << 30)
	DefaultMaxEntries           = 4096
	DefaultMaxLayers            = 256
	DefaultMaxMetadataBytes     = int64(4 << 20)
	maxTrailingZeroBytes        = int64(1 << 20)
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Limits bounds both parser work and the media an operator may import.
type Limits struct {
	MaxArchiveBytes      int64
	MaxUncompressedBytes int64
	MaxEntries           int
	MaxLayers            int
	MaxMetadataBytes     int64
}

func DefaultLimits() Limits {
	return Limits{
		MaxArchiveBytes: DefaultMaxArchiveBytes, MaxUncompressedBytes: DefaultMaxUncompressedBytes,
		MaxEntries: DefaultMaxEntries, MaxLayers: DefaultMaxLayers, MaxMetadataBytes: DefaultMaxMetadataBytes,
	}
}

func (l Limits) validate() error {
	if l.MaxArchiveBytes < 1 || l.MaxArchiveBytes > 1<<40 ||
		l.MaxUncompressedBytes < l.MaxArchiveBytes || l.MaxUncompressedBytes > 1<<41 ||
		l.MaxEntries < 1 || l.MaxEntries > 1<<20 || l.MaxLayers < 1 || l.MaxLayers > 4096 ||
		l.MaxMetadataBytes < 1 || l.MaxMetadataBytes > 64<<20 {
		return errors.New("OCI archive limits are invalid")
	}
	return nil
}

// Platform is the exact OCI platform selected from the archive config.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

// Identity is the signed image identity an archive must match. Repository is
// intentionally absent: an OCI manifest is repository-independent, while the
// publisher capsule and site policy bind its authorized repository provenance.
type Identity struct {
	ManifestDigest string   `json:"manifest_digest"`
	ConfigDigest   string   `json:"config_digest"`
	Platform       Platform `json:"platform"`
}

// Image is the verified, unambiguous image described by an archive.
type Image struct {
	Identity
	ManifestMediaType string   `json:"manifest_media_type"`
	ConfigMediaType   string   `json:"config_media_type"`
	LayerDigests      []string `json:"layer_digests"`
	RepoTags          []string `json:"repo_tags,omitempty"`
	BlobCount         int      `json:"blob_count"`
	BlobBytes         int64    `json:"blob_bytes"`
}

// Inspect validates all archive entries and blobs and returns its one selected
// image. The archive must be a regular file without group/world write access so
// its multiple bounded verification passes cannot be raced by another local user.
func Inspect(archivePath string, limits Limits) (Image, error) {
	return InspectContext(context.Background(), archivePath, limits)
}

// InspectContext is Inspect with cancellation propagated through every archive
// pass. Cancellation never converts a partially inspected archive into a valid
// image.
func InspectContext(ctx context.Context, archivePath string, limits Limits) (Image, error) {
	if err := contextError(ctx); err != nil {
		return Image{}, err
	}
	if err := limits.validate(); err != nil {
		return Image{}, err
	}
	info, err := os.Lstat(archivePath)
	if err != nil {
		return Image{}, fmt.Errorf("stat OCI archive: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return Image{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return Image{}, errors.New("OCI archive must be a regular file with no group/world write permission")
	}
	if info.Size() < 1 || info.Size() > limits.MaxArchiveBytes {
		return Image{}, fmt.Errorf("OCI archive size must be between 1 and %d bytes", limits.MaxArchiveBytes)
	}

	scan, err := scanArchiveContext(ctx, archivePath, limits)
	if err != nil {
		return Image{}, err
	}
	var layout imageLayout
	if err := decodeStrictJSONContext(ctx, scan.layout, &layout); err != nil || layout.ImageLayoutVersion != "1.0.0" {
		if contextErr := contextError(ctx); contextErr != nil {
			return Image{}, contextErr
		}
		return Image{}, errors.New("OCI archive has an invalid oci-layout document")
	}
	var index imageIndex
	if err := decodeStrictJSONContext(ctx, scan.index, &index); err != nil || index.SchemaVersion != 2 ||
		index.MediaType != ociIndexMediaType || len(index.Manifests) != 1 {
		if contextErr := contextError(ctx); contextErr != nil {
			return Image{}, contextErr
		}
		return Image{}, errors.New("OCI archive must contain one unambiguous OCI image manifest descriptor")
	}
	manifestDescriptor := index.Manifests[0]
	if err := validateDescriptor(manifestDescriptor, manifestMediaTypes); err != nil ||
		len(manifestDescriptor.URLs) != 0 || len(manifestDescriptor.Data) != 0 {
		return Image{}, fmt.Errorf("invalid OCI manifest descriptor: %w", nonNil(err, errors.New("embedded or remote manifest content is not allowed")))
	}
	if err := scan.matchBlob(manifestDescriptor); err != nil {
		return Image{}, err
	}
	manifestRaw, err := readBlobContext(ctx, archivePath, manifestDescriptor.Digest, manifestDescriptor.Size, limits)
	if err != nil {
		return Image{}, err
	}
	var manifest imageManifest
	if err := decodeStrictJSONContext(ctx, manifestRaw, &manifest); err != nil || manifest.SchemaVersion != 2 ||
		manifest.MediaType != manifestDescriptor.MediaType || manifest.ArtifactType != "" || manifest.Subject != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return Image{}, contextErr
		}
		return Image{}, errors.New("OCI image manifest is invalid or is an artifact manifest")
	}
	if err := validateDescriptor(manifest.Config, configMediaTypes); err != nil || len(manifest.Config.URLs) != 0 || len(manifest.Config.Data) != 0 {
		return Image{}, fmt.Errorf("invalid OCI config descriptor: %w", nonNil(err, errors.New("embedded or remote config content is not allowed")))
	}
	if len(manifest.Layers) == 0 || len(manifest.Layers) > limits.MaxLayers {
		return Image{}, fmt.Errorf("OCI image must contain 1 to %d layers", limits.MaxLayers)
	}
	if err := scan.matchBlob(manifest.Config); err != nil {
		return Image{}, err
	}
	layerDigests := make([]string, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		if err := contextError(ctx); err != nil {
			return Image{}, err
		}
		if err := validateDescriptor(layer, layerMediaTypes); err != nil || len(layer.URLs) != 0 || len(layer.Data) != 0 {
			return Image{}, fmt.Errorf("invalid OCI layer descriptor: %w", nonNil(err, errors.New("embedded or remote layer content is not allowed")))
		}
		if err := scan.matchBlob(layer); err != nil {
			return Image{}, err
		}
		layerDigests = append(layerDigests, layer.Digest)
	}
	configRaw, err := readBlobContext(ctx, archivePath, manifest.Config.Digest, manifest.Config.Size, limits)
	if err != nil {
		return Image{}, err
	}
	if err := rejectDuplicateJSONContext(ctx, configRaw); err != nil {
		return Image{}, fmt.Errorf("OCI image config is not strict JSON: %w", err)
	}
	var config imageConfig
	if err := contextError(ctx); err != nil {
		return Image{}, err
	}
	if err := decodeJSONContext(ctx, configRaw, &config); err != nil {
		return Image{}, fmt.Errorf("decode OCI image config: %w", err)
	}
	platform := Platform{OS: config.OS, Architecture: config.Architecture, Variant: config.Variant}
	if err := platform.validate(); err != nil {
		return Image{}, err
	}
	if len(config.Config.Volumes) != 0 || len(config.ContainerConfig.Volumes) != 0 {
		return Image{}, errors.New("OCI image declares writable volumes; Steward images must declare none")
	}
	if manifestDescriptor.Platform != nil && manifestDescriptor.Platform.normalized() != platform {
		return Image{}, errors.New("OCI index platform does not match the selected image config")
	}
	var repoTags []string
	if len(scan.dockerManifest) != 0 {
		repoTags, err = validateDockerManifestContext(ctx, scan.dockerManifest, manifest.Config, manifest.Layers)
		if err != nil {
			return Image{}, err
		}
	}
	if err := contextError(ctx); err != nil {
		return Image{}, err
	}
	return Image{
		Identity:          Identity{ManifestDigest: manifestDescriptor.Digest, ConfigDigest: manifest.Config.Digest, Platform: platform},
		ManifestMediaType: manifestDescriptor.MediaType, ConfigMediaType: manifest.Config.MediaType,
		LayerDigests: layerDigests, RepoTags: repoTags, BlobCount: len(scan.blobs), BlobBytes: scan.blobBytes,
	}, nil
}

// Verify requires an inspected archive to match an independently signed identity.
func Verify(archivePath string, expected Identity, limits Limits) (Image, error) {
	return VerifyContext(context.Background(), archivePath, expected, limits)
}

// VerifyContext is Verify with cancellation propagated through inspection and
// identity comparison.
func VerifyContext(ctx context.Context, archivePath string, expected Identity, limits Limits) (Image, error) {
	if err := contextError(ctx); err != nil {
		return Image{}, err
	}
	if err := expected.validate(); err != nil {
		return Image{}, fmt.Errorf("expected image identity: %w", err)
	}
	image, err := InspectContext(ctx, archivePath, limits)
	if err != nil {
		return Image{}, err
	}
	if err := contextError(ctx); err != nil {
		return Image{}, err
	}
	if image.Identity != expected {
		return Image{}, fmt.Errorf("OCI archive identity does not match the signed capsule: got %+v want %+v", image.Identity, expected)
	}
	return image, nil
}

func (i Identity) validate() error {
	if !digestPattern.MatchString(i.ManifestDigest) || !digestPattern.MatchString(i.ConfigDigest) {
		return errors.New("manifest and config must be canonical SHA-256 digests")
	}
	return i.Platform.validate()
}

func (p Platform) validate() error {
	if p.OS == "" || len(p.OS) > 32 || p.Architecture == "" || len(p.Architecture) > 32 || len(p.Variant) > 32 ||
		strings.ContainsAny(p.OS+p.Architecture+p.Variant, "\x00/\\") || !utf8.ValidString(p.OS+p.Architecture+p.Variant) {
		return errors.New("OCI image platform is invalid")
	}
	return nil
}

const (
	ociIndexMediaType        = "application/vnd.oci.image.index.v1+json"
	ociManifestMediaType     = "application/vnd.oci.image.manifest.v1+json"
	dockerManifestMediaType  = "application/vnd.docker.distribution.manifest.v2+json"
	ociConfigMediaType       = "application/vnd.oci.image.config.v1+json"
	dockerConfigMediaType    = "application/vnd.docker.container.image.v1+json"
	ociLayerMediaType        = "application/vnd.oci.image.layer.v1.tar"
	ociLayerGzipMediaType    = "application/vnd.oci.image.layer.v1.tar+gzip"
	ociLayerZstdMediaType    = "application/vnd.oci.image.layer.v1.tar+zstd"
	dockerLayerGzipMediaType = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	ociNonDistLayerMediaType = "application/vnd.oci.image.layer.nondistributable.v1.tar"
	ociNonDistGzipMediaType  = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
)

var (
	manifestMediaTypes = map[string]struct{}{ociManifestMediaType: {}, dockerManifestMediaType: {}}
	configMediaTypes   = map[string]struct{}{ociConfigMediaType: {}, dockerConfigMediaType: {}}
	layerMediaTypes    = map[string]struct{}{
		ociLayerMediaType: {}, ociLayerGzipMediaType: {}, ociLayerZstdMediaType: {}, dockerLayerGzipMediaType: {},
		ociNonDistLayerMediaType: {}, ociNonDistGzipMediaType: {},
	}
)

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	URLs        []string          `json:"urls,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Data        []byte            `json:"data,omitempty"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
}

type ociPlatform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os.version,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
	Variant      string   `json:"variant,omitempty"`
	Features     []string `json:"features,omitempty"`
}

func (p ociPlatform) normalized() Platform {
	return Platform{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant}
}

type imageLayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

type imageIndex struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Manifests     []descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type imageManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Subject       *descriptor       `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
	Config       struct {
		Volumes map[string]json.RawMessage `json:"Volumes"`
	} `json:"config"`
	ContainerConfig struct {
		Volumes map[string]json.RawMessage `json:"Volumes"`
	} `json:"container_config"`
}

type dockerManifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type blobInfo struct{ size int64 }

type archiveScan struct {
	layout, index, dockerManifest []byte
	blobs                         map[string]blobInfo
	blobBytes                     int64
}

func (s archiveScan) matchBlob(value descriptor) error {
	info, ok := s.blobs[value.Digest]
	if !ok {
		return fmt.Errorf("OCI archive is missing blob %s", value.Digest)
	}
	if info.size != value.Size {
		return fmt.Errorf("OCI descriptor size mismatch for %s: got %d want %d", value.Digest, info.size, value.Size)
	}
	return nil
}

func scanArchiveContext(ctx context.Context, archivePath string, limits Limits) (_ archiveScan, returnErr error) {
	if err := contextError(ctx); err != nil {
		return archiveScan{}, err
	}
	reader, closeReader, err := openArchiveContext(ctx, archivePath, limits)
	if err != nil {
		return archiveScan{}, err
	}
	defer func() {
		if closeErr := closeReader(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close OCI archive: %w", closeErr))
		}
	}()
	tarReader := tar.NewReader(reader)
	result := archiveScan{blobs: make(map[string]blobInfo)}
	seen := make(map[string]struct{})
	var total int64
	for entries := 0; ; entries++ {
		if err := contextError(ctx); err != nil {
			return archiveScan{}, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			if contextErr := contextError(ctx); contextErr != nil {
				return archiveScan{}, contextErr
			}
			break
		}
		if err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return archiveScan{}, contextErr
			}
			return archiveScan{}, fmt.Errorf("read OCI tar header: %w", err)
		}
		if entries >= limits.MaxEntries {
			return archiveScan{}, fmt.Errorf("OCI archive exceeds %d entries", limits.MaxEntries)
		}
		name := strings.TrimSuffix(header.Name, "/")
		if !validArchivePath(name) {
			return archiveScan{}, fmt.Errorf("OCI archive contains unsafe path %q", header.Name)
		}
		if _, duplicate := seen[name]; duplicate {
			return archiveScan{}, fmt.Errorf("OCI archive contains duplicate path %q", name)
		}
		seen[name] = struct{}{}
		if header.Typeflag == tar.TypeDir {
			if name != "blobs" && name != "blobs/sha256" {
				return archiveScan{}, fmt.Errorf("OCI archive contains unexpected directory %q", name)
			}
			continue
		}
		if !regularTarFile(header) {
			return archiveScan{}, fmt.Errorf("OCI archive path %q is not a regular file", name)
		}
		if header.Size < 0 || header.Size > limits.MaxUncompressedBytes-total {
			return archiveScan{}, errors.New("OCI archive exceeds its uncompressed byte limit")
		}
		total += header.Size
		switch name {
		case "oci-layout", "index.json", "manifest.json", "repositories":
			if header.Size > limits.MaxMetadataBytes {
				return archiveScan{}, fmt.Errorf("OCI metadata %q exceeds %d bytes", name, limits.MaxMetadataBytes)
			}
			raw, err := io.ReadAll(io.LimitReader(tarReader, limits.MaxMetadataBytes+1))
			if err != nil || int64(len(raw)) != header.Size {
				if contextErr := contextError(ctx); contextErr != nil {
					return archiveScan{}, contextErr
				}
				return archiveScan{}, fmt.Errorf("read OCI metadata %q: %w", name, nonNil(err, io.ErrUnexpectedEOF))
			}
			switch name {
			case "oci-layout":
				result.layout = raw
			case "index.json":
				result.index = raw
			case "manifest.json":
				result.dockerManifest = raw
			}
		default:
			const prefix = "blobs/sha256/"
			if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+64 || !lowerHex(name[len(prefix):]) {
				return archiveScan{}, fmt.Errorf("OCI archive contains unexpected path %q", name)
			}
			hash := sha256.New()
			written, err := io.Copy(hash, tarReader)
			if err != nil || written != header.Size {
				if contextErr := contextError(ctx); contextErr != nil {
					return archiveScan{}, contextErr
				}
				return archiveScan{}, fmt.Errorf("hash OCI blob %q: %w", name, nonNil(err, io.ErrUnexpectedEOF))
			}
			got := hex.EncodeToString(hash.Sum(nil))
			want := name[len(prefix):]
			if got != want {
				return archiveScan{}, fmt.Errorf("OCI blob %q digest mismatch", name)
			}
			digest := "sha256:" + want
			result.blobs[digest] = blobInfo{size: header.Size}
			result.blobBytes += header.Size
		}
	}
	if len(result.layout) == 0 || len(result.index) == 0 || len(result.blobs) == 0 {
		return archiveScan{}, errors.New("OCI archive is missing layout, index, or blobs")
	}
	trailing, err := io.ReadAll(io.LimitReader(reader, maxTrailingZeroBytes+1))
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return archiveScan{}, contextErr
		}
		return archiveScan{}, fmt.Errorf("read OCI archive trailer: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return archiveScan{}, err
	}
	zero, err := allZeroContext(ctx, trailing)
	if err != nil {
		return archiveScan{}, err
	}
	if int64(len(trailing)) > maxTrailingZeroBytes || !zero {
		return archiveScan{}, errors.New("OCI archive has non-zero or excessive trailing data")
	}
	return result, nil
}

func readBlobContext(ctx context.Context, archivePath, digest string, size int64, limits Limits) (_ []byte, returnErr error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !digestPattern.MatchString(digest) || size < 1 || size > limits.MaxMetadataBytes {
		return nil, fmt.Errorf("OCI metadata blob %s has invalid or excessive size", digest)
	}
	reader, closeReader, err := openArchiveContext(ctx, archivePath, limits)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := closeReader(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close OCI archive: %w", closeErr))
		}
	}()
	want := "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
	tarReader := tar.NewReader(reader)
	for {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			if contextErr := contextError(ctx); contextErr != nil {
				return nil, contextErr
			}
			return nil, fmt.Errorf("OCI archive is missing metadata blob %s", digest)
		}
		if err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return nil, contextErr
			}
			return nil, fmt.Errorf("read OCI tar header: %w", err)
		}
		if strings.TrimSuffix(header.Name, "/") != want {
			continue
		}
		if header.Size != size || !regularTarFile(header) {
			return nil, fmt.Errorf("OCI metadata blob %s changed between verification passes", digest)
		}
		raw, err := io.ReadAll(io.LimitReader(tarReader, limits.MaxMetadataBytes+1))
		if err != nil || int64(len(raw)) != size {
			if contextErr := contextError(ctx); contextErr != nil {
				return nil, contextErr
			}
			return nil, fmt.Errorf("read OCI metadata blob %s: %w", digest, nonNil(err, io.ErrUnexpectedEOF))
		}
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if "sha256:"+hex.EncodeToString(sum[:]) != digest {
			return nil, fmt.Errorf("OCI metadata blob %s changed between verification passes", digest)
		}
		return raw, nil
	}
}

// regularTarFile accepts both POSIX regular-file type encodings. archive/tar's
// TypeRegA name for the zero-byte form is deprecated, but existing OCI/Docker
// archives may still use that wire value.
func regularTarFile(header *tar.Header) bool {
	return header.Typeflag == tar.TypeReg || header.Typeflag == 0
}

func openArchiveContext(ctx context.Context, archivePath string, limits Limits) (io.Reader, func() error, error) {
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, nil, fmt.Errorf("open OCI archive: %w", err)
	}
	buffered := bufio.NewReader(contextReader{ctx: ctx, reader: io.LimitReader(file, limits.MaxArchiveBytes+1)})
	magic, err := buffered.Peek(2)
	if err != nil {
		_ = file.Close()
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, nil, contextErr
		}
		return nil, nil, fmt.Errorf("read OCI archive header: %w", err)
	}
	var source io.Reader = buffered
	var gzipReader *gzip.Reader
	if magic[0] == 0x1f && magic[1] == 0x8b {
		gzipReader, err = gzip.NewReader(buffered)
		if err != nil {
			_ = file.Close()
			if contextErr := contextError(ctx); contextErr != nil {
				return nil, nil, contextErr
			}
			return nil, nil, fmt.Errorf("open gzip OCI archive: %w", err)
		}
		source = gzipReader
	}
	limited := io.LimitReader(contextReader{ctx: ctx, reader: source}, limits.MaxUncompressedBytes+1)
	closeFn := func() error {
		var first error
		if gzipReader != nil {
			first = gzipReader.Close()
		}
		if err := file.Close(); first == nil {
			first = err
		}
		return first
	}
	return limited, closeFn, nil
}

func validateDockerManifestContext(ctx context.Context, raw []byte, config descriptor, layers []descriptor) ([]string, error) {
	if err := rejectDuplicateJSONContext(ctx, raw); err != nil {
		return nil, fmt.Errorf("Docker compatibility manifest is not strict JSON: %w", err)
	}
	var values []dockerManifestEntry
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := decodeJSONContext(ctx, raw, &values); err != nil || len(values) != 1 {
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, errors.New("Docker compatibility manifest must describe exactly one image")
	}
	wantConfig := "blobs/sha256/" + strings.TrimPrefix(config.Digest, "sha256:")
	if values[0].Config != wantConfig || len(values[0].Layers) != len(layers) {
		return nil, errors.New("Docker compatibility manifest disagrees with the OCI manifest")
	}
	for index, layer := range layers {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		want := "blobs/sha256/" + strings.TrimPrefix(layer.Digest, "sha256:")
		if values[0].Layers[index] != want {
			return nil, errors.New("Docker compatibility layer order disagrees with the OCI manifest")
		}
	}
	if len(values[0].RepoTags) > 64 {
		return nil, errors.New("Docker compatibility manifest has too many repository tags")
	}
	seen := make(map[string]struct{}, len(values[0].RepoTags))
	for _, tag := range values[0].RepoTags {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if tag == "" || len(tag) > 1024 || !utf8.ValidString(tag) || strings.ContainsAny(tag, "\x00\r\n") {
			return nil, errors.New("Docker compatibility manifest contains an invalid repository tag")
		}
		if _, duplicate := seen[tag]; duplicate {
			return nil, errors.New("Docker compatibility manifest contains a duplicate repository tag")
		}
		seen[tag] = struct{}{}
	}
	return append([]string(nil), values[0].RepoTags...), nil
}

func validateDescriptor(value descriptor, mediaTypes map[string]struct{}) error {
	if _, ok := mediaTypes[value.MediaType]; !ok || !digestPattern.MatchString(value.Digest) || value.Size < 1 {
		return errors.New("descriptor has unsupported media type, digest, or size")
	}
	return nil
}

func decodeStrictJSONContext(ctx context.Context, raw []byte, target any) error {
	if err := rejectDuplicateJSONContext(ctx, raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(contextReader{ctx: ctx, reader: bytes.NewReader(raw)})
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		return errors.New("JSON document must contain exactly one value")
	}
	return contextError(ctx)
}

func decodeJSONContext(ctx context.Context, raw []byte, target any) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	decoder := json.NewDecoder(contextReader{ctx: ctx, reader: bytes.NewReader(raw)})
	if err := decoder.Decode(target); err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		return errors.New("JSON document must contain exactly one value")
	}
	return contextError(ctx)
}

func rejectDuplicateJSONContext(ctx context.Context, raw []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(contextReader{ctx: ctx, reader: bytes.NewReader(raw)})
	decoder.UseNumber()
	if err := walkJSONContext(ctx, decoder); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		return errors.New("JSON document contains trailing data")
	}
	return contextError(ctx)
}

func walkJSONContext(ctx context.Context, decoder *json.Decoder) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	token, err := decoder.Token()
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			if err := contextError(ctx); err != nil {
				return err
			}
			keyToken, err := decoder.Token()
			if err != nil {
				if contextErr := contextError(ctx); contextErr != nil {
					return contextErr
				}
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not text")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON member %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONContext(ctx, decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			if contextErr := contextError(ctx); contextErr != nil {
				return contextErr
			}
			return errors.New("JSON object is not terminated")
		}
	case '[':
		for decoder.More() {
			if err := contextError(ctx); err != nil {
				return err
			}
			if err := walkJSONContext(ctx, decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			if contextErr := contextError(ctx); contextErr != nil {
				return contextErr
			}
			return errors.New("JSON array is not terminated")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := contextError(reader.ctx); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if contextErr := contextError(reader.ctx); contextErr != nil {
		return count, contextErr
	}
	return count, err
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (writer contextWriter) Write(buffer []byte) (int, error) {
	if err := contextError(writer.ctx); err != nil {
		return 0, err
	}
	count, err := writer.writer.Write(buffer)
	if contextErr := contextError(writer.ctx); contextErr != nil {
		return count, contextErr
	}
	return count, err
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("OCI operation context is required")
	}
	return ctx.Err()
}

func validArchivePath(value string) bool {
	return value != "" && len(value) <= 512 && !strings.HasPrefix(value, "/") && path.Clean(value) == value &&
		value != "." && !strings.HasPrefix(value, "../") && !strings.ContainsAny(value, "\\\x00") && utf8.ValidString(value)
}

func lowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func allZeroContext(ctx context.Context, raw []byte) (bool, error) {
	for index, value := range raw {
		if index%4096 == 0 {
			if err := contextError(ctx); err != nil {
				return false, err
			}
		}
		if value != 0 {
			return false, nil
		}
	}
	return true, contextError(ctx)
}

func nonNil(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}
