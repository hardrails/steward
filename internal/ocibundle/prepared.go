package ocibundle

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
)

// ArchiveIdentity identifies the exact compressed or uncompressed source bytes
// supplied by an operator. It is separate from Image identity because two
// archives can contain the same OCI image while differing in metadata or
// unreferenced content.
type ArchiveIdentity struct {
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
}

// SourceInspection binds the exact source archive bytes to the image identity
// parsed from those same bytes. It is suitable for constructing a signed
// offline release before a later PrepareBound call verifies the archive again.
type SourceInspection struct {
	Archive           ArchiveIdentity `json:"archive"`
	Image             Image           `json:"image"`
	UncompressedBytes int64           `json:"-"`
}

func (identity ArchiveIdentity) validate(limits Limits) error {
	if !digestPattern.MatchString(identity.Digest) {
		return errors.New("archive digest must be one sha256 digest")
	}
	if identity.Bytes < 1 || identity.Bytes > limits.MaxArchiveBytes {
		return fmt.Errorf("archive size must be between 1 and %d bytes", limits.MaxArchiveBytes)
	}
	return nil
}

// InspectSource snapshots an untrusted archive through one stable descriptor,
// hashes it while copying, and inspects only the sealed private snapshot. It
// does not retain the source bytes after returning or build a Docker load
// archive.
func InspectSource(archivePath string, limits Limits) (SourceInspection, error) {
	return InspectSourceContext(context.Background(), archivePath, limits)
}

// InspectSourceContext is InspectSource with cancellation propagated through
// snapshotting and inspection. Its private snapshot is removed on every error,
// including cancellation.
func InspectSourceContext(ctx context.Context, archivePath string, limits Limits) (SourceInspection, error) {
	if err := contextError(ctx); err != nil {
		return SourceInspection{}, err
	}
	if err := limits.validate(); err != nil {
		return SourceInspection{}, err
	}
	directory, err := os.MkdirTemp("", ".steward-oci-inspect-")
	if err != nil {
		return SourceInspection{}, fmt.Errorf("create private OCI inspection directory: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(directory) }
	snapshotPath := directory + string(os.PathSeparator) + "source.snapshot"
	archive, err := snapshotArchiveIdentityContext(ctx, archivePath, snapshotPath, limits)
	if err != nil {
		return SourceInspection{}, errors.Join(err, cleanup())
	}
	image, err := InspectContext(ctx, snapshotPath, limits)
	if err != nil {
		return SourceInspection{}, errors.Join(err, cleanup())
	}
	if err := contextError(ctx); err != nil {
		return SourceInspection{}, errors.Join(err, cleanup())
	}
	if err := cleanup(); err != nil {
		return SourceInspection{}, fmt.Errorf("remove private OCI inspection directory: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return SourceInspection{}, err
	}
	return SourceInspection{
		Archive: archive, Image: image, UncompressedBytes: image.uncompressedBytes,
	}, nil
}

// InspectRootSource is InspectSource for an archive name confined beneath a
// descriptor-pinned root. Mutable ancestor renames and escaping symlinks cannot
// redirect the source open outside that root.
func InspectRootSource(root *os.Root, archiveName string, limits Limits) (SourceInspection, error) {
	return InspectRootSourceContext(context.Background(), root, archiveName, limits)
}

// InspectRootSourceContext is InspectRootSource with cancellation propagated
// through root-confined snapshotting and inspection.
func InspectRootSourceContext(
	ctx context.Context,
	root *os.Root,
	archiveName string,
	limits Limits,
) (SourceInspection, error) {
	if err := contextError(ctx); err != nil {
		return SourceInspection{}, err
	}
	if root == nil || archiveName == "" {
		return SourceInspection{}, errors.New("OCI archive root and name are required")
	}
	if err := limits.validate(); err != nil {
		return SourceInspection{}, err
	}
	directory, err := os.MkdirTemp("", ".steward-oci-inspect-")
	if err != nil {
		return SourceInspection{}, fmt.Errorf("create private OCI inspection directory: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(directory) }
	snapshotPath := directory + string(os.PathSeparator) + "source.snapshot"
	archive, err := snapshotArchiveRootIdentityContext(
		ctx, root, archiveName, snapshotPath, limits,
	)
	if err != nil {
		return SourceInspection{}, errors.Join(err, cleanup())
	}
	image, err := InspectContext(ctx, snapshotPath, limits)
	if err != nil {
		return SourceInspection{}, errors.Join(err, cleanup())
	}
	if err := contextError(ctx); err != nil {
		return SourceInspection{}, errors.Join(err, cleanup())
	}
	if err := cleanup(); err != nil {
		return SourceInspection{}, fmt.Errorf("remove private OCI inspection directory: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return SourceInspection{}, err
	}
	return SourceInspection{
		Archive: archive, Image: image, UncompressedBytes: image.uncompressedBytes,
	}, nil
}

// Prepared is a verified, tag-free, minimal image archive held by one open,
// unlinked file descriptor. Reader never resolves the caller's source path, so
// renames or replacements after Prepare cannot change the bytes Docker sees.
// Callers must Close a Prepared archive when the Docker request finishes.
type Prepared struct {
	Image   Image
	Archive ArchiveIdentity

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
	return PrepareContext(context.Background(), archivePath, expected, limits)
}

// PrepareContext is Prepare with cancellation propagated through snapshotting,
// verification, sanitization, and the final verification pass.
func PrepareContext(ctx context.Context, archivePath string, expected Identity, limits Limits) (*Prepared, error) {
	return prepare(ctx, archivePath, expected, ArchiveIdentity{}, false, limits)
}

// PrepareBound additionally requires the exact source archive bytes to match a
// signed digest and size. The comparison uses the same private snapshot later
// verified and sanitized for Docker, so a caller never authorizes one pathname
// read and imports another.
func PrepareBound(archivePath string, expected Identity, archive ArchiveIdentity, limits Limits) (*Prepared, error) {
	return PrepareBoundContext(context.Background(), archivePath, expected, archive, limits)
}

// PrepareBoundContext is PrepareBound with cancellation propagated through
// every preflight pass. A canceled call returns no Prepared archive and closes
// and removes all private intermediate artifacts.
func PrepareBoundContext(ctx context.Context, archivePath string, expected Identity, archive ArchiveIdentity, limits Limits) (*Prepared, error) {
	return prepare(ctx, archivePath, expected, archive, true, limits)
}

func prepare(ctx context.Context, archivePath string, expected Identity, expectedArchive ArchiveIdentity, bound bool, limits Limits) (*Prepared, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if err := expected.validate(); err != nil {
		return nil, fmt.Errorf("expected image identity: %w", err)
	}
	if bound {
		if err := expectedArchive.validate(limits); err != nil {
			return nil, fmt.Errorf("expected archive identity: %w", err)
		}
	}
	directory, err := os.MkdirTemp("", ".steward-oci-")
	if err != nil {
		return nil, fmt.Errorf("create private OCI preparation directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }

	snapshotPath := directory + string(os.PathSeparator) + "source.snapshot"
	archiveIdentity, err := snapshotArchiveIdentityContext(ctx, archivePath, snapshotPath, limits)
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		cleanup()
		return nil, err
	}
	if bound && archiveIdentity != expectedArchive {
		cleanup()
		return nil, errors.New("OCI archive does not match the signed archive digest and size")
	}
	image, err := VerifyContext(ctx, snapshotPath, expected, limits)
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
	if err := writeSanitizedArchiveContext(ctx, snapshotPath, load, image, limits); err != nil {
		return fail(err)
	}
	if err := load.Sync(); err != nil {
		return fail(fmt.Errorf("sync private Docker load archive: %w", err))
	}
	if err := contextError(ctx); err != nil {
		return fail(err)
	}
	info, err := load.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat private Docker load archive: %w", err))
	}
	if err := contextError(ctx); err != nil {
		return fail(err)
	}
	if info.Size() < 1 || info.Size() > limits.MaxUncompressedBytes+int64(limits.MaxEntries+8)*1024 {
		return fail(errors.New("sanitized Docker load archive has an invalid size"))
	}
	if err := load.Chmod(0o400); err != nil {
		return fail(fmt.Errorf("seal private Docker load archive: %w", err))
	}
	if err := contextError(ctx); err != nil {
		return fail(err)
	}
	if err := load.Close(); err != nil {
		return fail(fmt.Errorf("close writable Docker load archive: %w", err))
	}
	load = nil
	sanitizedImage, err := VerifyContext(ctx, loadPath, expected, limits)
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
	if err := contextError(ctx); err != nil {
		return fail(err)
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
	if err := contextError(ctx); err != nil {
		_ = load.Close()
		return nil, err
	}
	return &Prepared{Image: sanitizedImage, Archive: archiveIdentity, file: load, size: info.Size()}, nil
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
	return snapshotArchiveContext(context.Background(), sourcePath, snapshotPath, limits)
}

func snapshotArchiveContext(ctx context.Context, sourcePath, snapshotPath string, limits Limits) error {
	_, err := snapshotArchiveIdentityContext(ctx, sourcePath, snapshotPath, limits)
	return err
}

func snapshotArchiveIdentityContext(ctx context.Context, sourcePath, snapshotPath string, limits Limits) (_ ArchiveIdentity, returnErr error) {
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	before, err := os.Lstat(sourcePath)
	if err != nil {
		return ArchiveIdentity{}, fmt.Errorf("stat OCI archive: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 {
		return ArchiveIdentity{}, errors.New("OCI archive must be a regular file with no group/world write permission")
	}
	if before.Size() < 1 || before.Size() > limits.MaxArchiveBytes {
		return ArchiveIdentity{}, fmt.Errorf("OCI archive size must be between 1 and %d bytes", limits.MaxArchiveBytes)
	}
	// O_NONBLOCK is ignored for regular files but prevents an attacker who can
	// rename entries in the parent directory from swapping a validated path to a
	// FIFO and hanging the privileged importer between Lstat and Open.
	source, err := os.OpenFile(sourcePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ArchiveIdentity{}, fmt.Errorf("open OCI archive: %w", err)
	}
	defer func() { _ = source.Close() }()
	return snapshotOpenedArchiveIdentityContext(ctx, before, source, snapshotPath, limits)
}

func snapshotArchiveRootIdentityContext(
	ctx context.Context,
	root *os.Root,
	sourceName string,
	snapshotPath string,
	limits Limits,
) (_ ArchiveIdentity, returnErr error) {
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	before, err := root.Lstat(sourceName)
	if err != nil {
		return ArchiveIdentity{}, fmt.Errorf("stat root-confined OCI archive: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 {
		return ArchiveIdentity{}, errors.New("root-confined OCI archive must be a regular file with no group/world write permission")
	}
	if before.Size() < 1 || before.Size() > limits.MaxArchiveBytes {
		return ArchiveIdentity{}, fmt.Errorf(
			"root-confined OCI archive size must be between 1 and %d bytes",
			limits.MaxArchiveBytes,
		)
	}
	source, err := root.OpenFile(sourceName, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ArchiveIdentity{}, fmt.Errorf("open root-confined OCI archive: %w", err)
	}
	defer func() { _ = source.Close() }()
	return snapshotOpenedArchiveIdentityContext(ctx, before, source, snapshotPath, limits)
}

func snapshotOpenedArchiveIdentityContext(
	ctx context.Context,
	before os.FileInfo,
	source *os.File,
	snapshotPath string,
	limits Limits,
) (_ ArchiveIdentity, returnErr error) {
	opened, err := source.Stat()
	if err != nil {
		return ArchiveIdentity{}, fmt.Errorf("stat open OCI archive: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	if !opened.Mode().IsRegular() || opened.Mode().Perm()&0o022 != 0 || !os.SameFile(before, opened) {
		return ArchiveIdentity{}, errors.New("OCI archive changed while it was opened")
	}

	snapshot, err := os.OpenFile(snapshotPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ArchiveIdentity{}, fmt.Errorf("create private OCI snapshot: %w", err)
	}
	snapshotOpen := true
	defer func() {
		if snapshotOpen {
			if closeErr := snapshot.Close(); closeErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close private OCI snapshot: %w", closeErr))
			}
		}
		if returnErr != nil {
			if removeErr := os.Remove(snapshotPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove incomplete private OCI snapshot: %w", removeErr))
			}
		}
	}()
	hasher := sha256.New()
	snapshotWriter := contextWriter{ctx: ctx, writer: io.MultiWriter(snapshot, hasher)}
	sourceReader := contextReader{ctx: ctx, reader: io.LimitReader(source, limits.MaxArchiveBytes+1)}
	copied, err := io.Copy(snapshotWriter, sourceReader)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return ArchiveIdentity{}, contextErr
		}
		return ArchiveIdentity{}, fmt.Errorf("snapshot OCI archive: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	if copied != before.Size() || copied > limits.MaxArchiveBytes {
		return ArchiveIdentity{}, errors.New("OCI archive changed size while it was snapshotted")
	}
	after, err := source.Stat()
	if err != nil {
		return ArchiveIdentity{}, fmt.Errorf("stat snapshotted OCI archive: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	if !os.SameFile(opened, after) || after.Size() != opened.Size() || after.Mode().Perm()&0o022 != 0 {
		return ArchiveIdentity{}, errors.New("OCI archive changed while it was snapshotted")
	}
	if err := snapshot.Sync(); err != nil {
		return ArchiveIdentity{}, fmt.Errorf("sync private OCI snapshot: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	if err := snapshot.Chmod(0o400); err != nil {
		return ArchiveIdentity{}, fmt.Errorf("seal private OCI snapshot: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	if err := snapshot.Close(); err != nil {
		return ArchiveIdentity{}, fmt.Errorf("close private OCI snapshot: %w", err)
	}
	snapshotOpen = false
	if err := contextError(ctx); err != nil {
		return ArchiveIdentity{}, err
	}
	return ArchiveIdentity{
		Digest: fmt.Sprintf("sha256:%x", hasher.Sum(nil)),
		Bytes:  copied,
	}, nil
}

func writeSanitizedArchive(snapshotPath string, output io.Writer, image Image, limits Limits) error {
	return writeSanitizedArchiveContext(context.Background(), snapshotPath, output, image, limits)
}

func writeSanitizedArchiveContext(ctx context.Context, snapshotPath string, output io.Writer, image Image, limits Limits) (returnErr error) {
	if err := contextError(ctx); err != nil {
		return err
	}
	scan, err := scanArchiveContext(ctx, snapshotPath, limits)
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
	if err := contextError(ctx); err != nil {
		return err
	}
	layers := make([]string, len(image.LayerDigests))
	for index, digest := range image.LayerDigests {
		if err := contextError(ctx); err != nil {
			return err
		}
		layers[index] = blobPath(digest)
	}
	dockerManifestRaw, err := json.Marshal([]dockerManifestEntry{{
		Config: blobPath(image.ConfigDigest), RepoTags: []string{}, Layers: layers,
	}})
	if err != nil {
		return fmt.Errorf("encode sanitized Docker manifest: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return err
	}

	wanted := make(map[string]blobInfo, len(image.LayerDigests)+2)
	for _, digest := range append(append([]string{}, image.ManifestDigest, image.ConfigDigest), image.LayerDigests...) {
		if err := contextError(ctx); err != nil {
			return err
		}
		info, ok := scan.blobs[digest]
		if !ok {
			return fmt.Errorf("verified OCI blob %s disappeared from private snapshot", digest)
		}
		wanted[blobPath(digest)] = info
	}

	tarWriter := tar.NewWriter(contextWriter{ctx: ctx, writer: output})
	writeBytes := func(name string, raw []byte) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := writeSanitizedHeader(tarWriter, name, int64(len(raw))); err != nil {
			return err
		}
		if _, err := tarWriter.Write(raw); err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return contextErr
			}
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

	reader, closeReader, err := openArchiveContext(ctx, snapshotPath, limits)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closeReader(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close private OCI snapshot: %w", closeErr))
		}
	}()
	tarReader := tar.NewReader(reader)
	seen := make(map[string]struct{}, len(wanted))
	for {
		if err := contextError(ctx); err != nil {
			return err
		}
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return contextErr
			}
			return fmt.Errorf("read private OCI snapshot: %w", nextErr)
		}
		name := strings.TrimSuffix(header.Name, "/")
		info, keep := wanted[name]
		if !keep {
			continue
		}
		if header.Size != info.size || !regularTarFile(header) {
			return fmt.Errorf("verified OCI blob %q changed before sanitization", name)
		}
		if err := writeSanitizedHeader(tarWriter, name, header.Size); err != nil {
			return err
		}
		written, copyErr := io.CopyN(tarWriter, tarReader, header.Size)
		if copyErr != nil || written != header.Size {
			if contextErr := contextError(ctx); contextErr != nil {
				return contextErr
			}
			return fmt.Errorf("copy sanitized OCI blob %q: %w", name, nonNil(copyErr, io.ErrUnexpectedEOF))
		}
		seen[name] = struct{}{}
	}
	if len(seen) != len(wanted) {
		return errors.New("private OCI snapshot is missing a verified blob during sanitization")
	}
	if err := tarWriter.Close(); err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		return fmt.Errorf("finish sanitized Docker load archive: %w", err)
	}
	return contextError(ctx)
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
