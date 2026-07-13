package ocibundle

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
)

// Prepared is a verified, tag-free, minimal image archive held by one open,
// unlinked file descriptor. Reader never resolves the caller's source path, so
// renames or replacements after Prepare cannot change the bytes Docker sees.
// Callers must Close a Prepared archive when the Docker request finishes.
type Prepared struct {
	Image Image

	mu     sync.Mutex
	file   *os.File
	size   int64
	closed bool
}

// Prepare snapshots an untrusted archive through one open source descriptor,
// verifies the private snapshot against the signed identity, and builds the
// only archive that may be sent to Docker. The load archive has no repository
// tags or repositories file and contains only the selected manifest, config,
// and layer blobs.
func Prepare(archivePath string, expected Identity, limits Limits) (*Prepared, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if err := expected.validate(); err != nil {
		return nil, fmt.Errorf("expected image identity: %w", err)
	}
	directory, err := os.MkdirTemp("", ".steward-oci-")
	if err != nil {
		return nil, fmt.Errorf("create private OCI preparation directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }

	snapshotPath := directory + string(os.PathSeparator) + "source.snapshot"
	if err := snapshotArchive(archivePath, snapshotPath, limits); err != nil {
		cleanup()
		return nil, err
	}
	image, err := Verify(snapshotPath, expected, limits)
	if err != nil {
		cleanup()
		return nil, err
	}

	loadPath := directory + string(os.PathSeparator) + "docker-load.tar"
	load, err := os.OpenFile(loadPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("create private Docker load archive: %w", err)
	}
	fail := func(cause error) (*Prepared, error) {
		if load != nil {
			_ = load.Close()
		}
		cleanup()
		return nil, cause
	}
	if err := writeSanitizedArchive(snapshotPath, load, image, limits); err != nil {
		return fail(err)
	}
	if err := load.Sync(); err != nil {
		return fail(fmt.Errorf("sync private Docker load archive: %w", err))
	}
	info, err := load.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat private Docker load archive: %w", err))
	}
	if info.Size() < 1 || info.Size() > limits.MaxUncompressedBytes+int64(limits.MaxEntries+8)*1024 {
		return fail(errors.New("sanitized Docker load archive has an invalid size"))
	}
	if err := load.Chmod(0o400); err != nil {
		return fail(fmt.Errorf("seal private Docker load archive: %w", err))
	}
	if err := load.Close(); err != nil {
		return fail(fmt.Errorf("close writable Docker load archive: %w", err))
	}
	load = nil
	sanitizedImage, err := Verify(loadPath, expected, limits)
	if err != nil {
		return fail(fmt.Errorf("verify sanitized Docker load archive: %w", err))
	}
	if len(sanitizedImage.RepoTags) != 0 || sanitizedImage.BlobCount != referencedBlobCount(image) {
		return fail(errors.New("sanitized Docker load archive retained tags or unreferenced blobs"))
	}
	load, err = os.Open(loadPath)
	if err != nil {
		return fail(fmt.Errorf("open sealed Docker load archive: %w", err))
	}
	sealedInfo, err := load.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat sealed Docker load archive: %w", err))
	}
	if !sealedInfo.Mode().IsRegular() || sealedInfo.Mode().Perm() != 0o400 || sealedInfo.Size() != info.Size() || !os.SameFile(info, sealedInfo) {
		return fail(errors.New("sealed Docker load archive changed while it was reopened"))
	}
	if err := os.Remove(snapshotPath); err != nil {
		return fail(fmt.Errorf("remove private OCI snapshot: %w", err))
	}
	if err := os.Remove(loadPath); err != nil {
		return fail(fmt.Errorf("unlink private Docker load archive: %w", err))
	}
	if err := os.Remove(directory); err != nil {
		_ = load.Close()
		return nil, fmt.Errorf("remove private OCI preparation directory: %w", err)
	}
	return &Prepared{Image: sanitizedImage, file: load, size: info.Size()}, nil
}

// Reader returns a fresh bounded view of the already-open load descriptor.
// It is safe to call more than once; every view contains the same immutable
// bytes and has an independent offset.
func (p *Prepared) Reader() (io.Reader, error) {
	if p == nil {
		return nil, errors.New("prepared OCI archive is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.file == nil {
		return nil, errors.New("prepared OCI archive is closed")
	}
	return io.NewSectionReader(p.file, 0, p.size), nil
}

// Close releases the private load descriptor. It is idempotent.
func (p *Prepared) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	return err
}

func snapshotArchive(sourcePath, snapshotPath string, limits Limits) error {
	before, err := os.Lstat(sourcePath)
	if err != nil {
		return fmt.Errorf("stat OCI archive: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 {
		return errors.New("OCI archive must be a regular file with no group/world write permission")
	}
	if before.Size() < 1 || before.Size() > limits.MaxArchiveBytes {
		return fmt.Errorf("OCI archive size must be between 1 and %d bytes", limits.MaxArchiveBytes)
	}
	// O_NONBLOCK is ignored for regular files but prevents an attacker who can
	// rename entries in the parent directory from swapping a validated path to a
	// FIFO and hanging the privileged importer between Lstat and Open.
	source, err := os.OpenFile(sourcePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open OCI archive: %w", err)
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil {
		return fmt.Errorf("stat open OCI archive: %w", err)
	}
	if !opened.Mode().IsRegular() || opened.Mode().Perm()&0o022 != 0 || !os.SameFile(before, opened) {
		return errors.New("OCI archive changed while it was opened")
	}

	snapshot, err := os.OpenFile(snapshotPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private OCI snapshot: %w", err)
	}
	closeSnapshot := true
	defer func() {
		if closeSnapshot {
			_ = snapshot.Close()
		}
	}()
	copied, err := io.Copy(snapshot, io.LimitReader(source, limits.MaxArchiveBytes+1))
	if err != nil {
		return fmt.Errorf("snapshot OCI archive: %w", err)
	}
	if copied != before.Size() || copied > limits.MaxArchiveBytes {
		return errors.New("OCI archive changed size while it was snapshotted")
	}
	after, err := source.Stat()
	if err != nil {
		return fmt.Errorf("stat snapshotted OCI archive: %w", err)
	}
	if !os.SameFile(opened, after) || after.Size() != opened.Size() || after.Mode().Perm()&0o022 != 0 {
		return errors.New("OCI archive changed while it was snapshotted")
	}
	if err := snapshot.Sync(); err != nil {
		return fmt.Errorf("sync private OCI snapshot: %w", err)
	}
	if err := snapshot.Chmod(0o400); err != nil {
		return fmt.Errorf("seal private OCI snapshot: %w", err)
	}
	if err := snapshot.Close(); err != nil {
		return fmt.Errorf("close private OCI snapshot: %w", err)
	}
	closeSnapshot = false
	return nil
}

func writeSanitizedArchive(snapshotPath string, output io.Writer, image Image, limits Limits) error {
	scan, err := scanArchive(snapshotPath, limits)
	if err != nil {
		return fmt.Errorf("rescan private OCI snapshot: %w", err)
	}
	manifestInfo, ok := scan.blobs[image.ManifestDigest]
	if !ok {
		return errors.New("verified OCI manifest disappeared from private snapshot")
	}
	platform := ociPlatform{OS: image.Platform.OS, Architecture: image.Platform.Architecture, Variant: image.Platform.Variant}
	indexRaw, err := json.Marshal(imageIndex{
		SchemaVersion: 2,
		MediaType:     ociIndexMediaType,
		Manifests: []descriptor{{
			MediaType: image.ManifestMediaType,
			Digest:    image.ManifestDigest,
			Size:      manifestInfo.size,
			Annotations: map[string]string{
				"config.digest": image.ConfigDigest,
			},
			Platform: &platform,
		}},
	})
	if err != nil {
		return fmt.Errorf("encode sanitized OCI index: %w", err)
	}
	layers := make([]string, len(image.LayerDigests))
	for index, digest := range image.LayerDigests {
		layers[index] = blobPath(digest)
	}
	dockerManifestRaw, err := json.Marshal([]dockerManifestEntry{{
		Config: blobPath(image.ConfigDigest), RepoTags: []string{}, Layers: layers,
	}})
	if err != nil {
		return fmt.Errorf("encode sanitized Docker manifest: %w", err)
	}

	wanted := make(map[string]blobInfo, len(image.LayerDigests)+2)
	for _, digest := range append(append([]string{}, image.ManifestDigest, image.ConfigDigest), image.LayerDigests...) {
		info, ok := scan.blobs[digest]
		if !ok {
			return fmt.Errorf("verified OCI blob %s disappeared from private snapshot", digest)
		}
		wanted[blobPath(digest)] = info
	}

	tarWriter := tar.NewWriter(output)
	writeBytes := func(name string, raw []byte) error {
		if err := writeSanitizedHeader(tarWriter, name, int64(len(raw))); err != nil {
			return err
		}
		if _, err := tarWriter.Write(raw); err != nil {
			return fmt.Errorf("write sanitized archive path %q: %w", name, err)
		}
		return nil
	}
	if err := writeBytes("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)); err != nil {
		return err
	}
	if err := writeBytes("index.json", indexRaw); err != nil {
		return err
	}
	if err := writeBytes("manifest.json", dockerManifestRaw); err != nil {
		return err
	}

	reader, closeReader, err := openArchive(snapshotPath, limits)
	if err != nil {
		return err
	}
	tarReader := tar.NewReader(reader)
	seen := make(map[string]struct{}, len(wanted))
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = closeReader()
			return fmt.Errorf("read private OCI snapshot: %w", nextErr)
		}
		name := strings.TrimSuffix(header.Name, "/")
		info, keep := wanted[name]
		if !keep {
			continue
		}
		if header.Size != info.size || !regularTarFile(header) {
			_ = closeReader()
			return fmt.Errorf("verified OCI blob %q changed before sanitization", name)
		}
		if err := writeSanitizedHeader(tarWriter, name, header.Size); err != nil {
			_ = closeReader()
			return err
		}
		written, copyErr := io.CopyN(tarWriter, tarReader, header.Size)
		if copyErr != nil || written != header.Size {
			_ = closeReader()
			return fmt.Errorf("copy sanitized OCI blob %q: %w", name, nonNil(copyErr, io.ErrUnexpectedEOF))
		}
		seen[name] = struct{}{}
	}
	if err := closeReader(); err != nil {
		return fmt.Errorf("close private OCI snapshot: %w", err)
	}
	if len(seen) != len(wanted) {
		return errors.New("private OCI snapshot is missing a verified blob during sanitization")
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("finish sanitized Docker load archive: %w", err)
	}
	return nil
}

func writeSanitizedHeader(writer *tar.Writer, name string, size int64) error {
	header := &tar.Header{Name: name, Mode: 0o444, Size: size, Typeflag: tar.TypeReg}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write sanitized archive header %q: %w", name, err)
	}
	return nil
}

func blobPath(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func referencedBlobCount(image Image) int {
	digests := map[string]struct{}{image.ManifestDigest: {}, image.ConfigDigest: {}}
	for _, digest := range image.LayerDigests {
		digests[digest] = struct{}{}
	}
	return len(digests)
}
