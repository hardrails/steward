// Package controlbackup creates and restores bounded, self-describing backups
// of the default Steward Control state and identity set.
package controlbackup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/controlwitness"
)

const (
	SchemaV1         = "steward.control-backup.v1"
	ReportSchemaV1   = "steward.control-backup-report.v1"
	manifestName     = "manifest.json"
	payloadPrefix    = "state/"
	maxFiles         = 128
	maxManifestBytes = 64 << 10
	maxFileBytes     = 128 << 20
	maxPayloadBytes  = 256 << 20
	maxArchiveBytes  = maxPayloadBytes + (2 << 20)
)

var requiredIdentityFiles = []string{
	"auth.key",
	"controller.private.pem",
	"controller.public.pem",
	"witness.private.pem",
	"witness.public.pem",
}

type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	CreatedAt     string         `json:"created_at"`
	Generation    uint64         `json:"generation"`
	Sequence      uint64         `json:"sequence"`
	Files         []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

type Report struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	ArchiveSHA256 string `json:"archive_sha256"`
	CreatedAt     string `json:"created_at"`
	Generation    uint64 `json:"generation"`
	Sequence      uint64 `json:"sequence"`
	Files         int    `json:"files"`
	PayloadBytes  int64  `json:"payload_bytes"`
}

type openedFile struct {
	manifest ManifestFile
	file     *os.File
	before   os.FileInfo
}

// Create locks and validates a stopped Control store, then writes one new
// owner-only archive. The default identity files must live in the state
// directory so restoring the archive does not silently create a new authority.
func Create(stateDirectory, output string, now time.Time) (report Report, err error) {
	if err := validCleanAbsolute(stateDirectory, false); err != nil {
		return Report{}, fmt.Errorf("control backup state directory: %w", err)
	}
	if err := validCleanAbsolute(output, false); err != nil {
		return Report{}, fmt.Errorf("control backup output: %w", err)
	}
	if now.IsZero() {
		return Report{}, errors.New("control backup creation time is required")
	}
	inside, err := pathInside(stateDirectory, output)
	if err != nil {
		return Report{}, err
	}
	if inside {
		return Report{}, errors.New("control backup output must be outside the state directory")
	}

	store, err := controlstore.Open(stateDirectory, controlstore.DefaultLimits())
	if err != nil {
		return Report{}, fmt.Errorf("open stopped Control state: %w", err)
	}
	defer func() {
		if closeErr := store.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	status, err := store.Status()
	if err != nil {
		return Report{}, err
	}
	if err := validateDefaultIdentitySet(stateDirectory); err != nil {
		return Report{}, err
	}
	files, err := openStateFiles(stateDirectory)
	if err != nil {
		return Report{}, err
	}
	defer closeOpened(files)
	manifest := Manifest{
		SchemaVersion: SchemaV1, CreatedAt: now.UTC().Format(time.RFC3339Nano),
		Generation: status.Generation, Sequence: status.Sequence,
		Files: make([]ManifestFile, len(files)),
	}
	for index := range files {
		manifest.Files[index] = files[index].manifest
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return Report{}, err
	}
	manifestRaw = append(manifestRaw, '\n')
	if len(manifestRaw) > maxManifestBytes {
		return Report{}, errors.New("control backup manifest exceeds its limit")
	}
	archive, err := createExclusive(output, 0o600)
	if err != nil {
		return Report{}, fmt.Errorf("create control backup: %w", err)
	}
	keep := false
	defer func() {
		_ = archive.Close()
		if !keep {
			_ = os.Remove(output)
		}
	}()
	hash := sha256.New()
	tarWriter := tar.NewWriter(io.MultiWriter(archive, hash))
	if err := writeTarEntry(tarWriter, manifestName, 0o600, manifestRaw); err != nil {
		return Report{}, err
	}
	for _, opened := range files {
		if _, err := opened.file.Seek(0, io.SeekStart); err != nil {
			return Report{}, fmt.Errorf("rewind Control state file %q: %w", opened.manifest.Name, err)
		}
		header := &tar.Header{
			Name: payloadPrefix + opened.manifest.Name, Mode: int64(opened.manifest.Mode),
			Size: opened.manifest.Size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return Report{}, fmt.Errorf("write Control backup header: %w", err)
		}
		written, err := io.CopyN(tarWriter, opened.file, opened.manifest.Size)
		if err != nil || written != opened.manifest.Size {
			return Report{}, fmt.Errorf("write Control state file %q: %w", opened.manifest.Name, err)
		}
		after, statErr := opened.file.Stat()
		if statErr != nil || !sameFile(opened.before, after) {
			return Report{}, fmt.Errorf("Control state file %q changed during backup", opened.manifest.Name)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return Report{}, fmt.Errorf("finish Control backup: %w", err)
	}
	if err := archive.Sync(); err != nil {
		return Report{}, fmt.Errorf("sync Control backup: %w", err)
	}
	if err := archive.Close(); err != nil {
		return Report{}, fmt.Errorf("close Control backup: %w", err)
	}
	if err := syncDirectory(filepath.Dir(output)); err != nil {
		return Report{}, err
	}
	keep = true
	return reportFromManifest(manifest, "sha256:"+hex.EncodeToString(hash.Sum(nil))), nil
}

// Verify validates the complete archive without extracting it.
func Verify(archivePath string) (Report, error) {
	return inspect(archivePath, nil)
}

// Restore verifies and extracts an archive into a new state directory. The
// destination is published only after the restored store and identities pass
// their normal readers. Existing destinations are never overwritten.
func Restore(archivePath, destination string) (report Report, err error) {
	if err := validCleanAbsolute(destination, false); err != nil {
		return Report{}, fmt.Errorf("Control restore destination: %w", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return Report{}, errors.New("Control restore destination already exists")
		}
		return Report{}, fmt.Errorf("inspect Control restore destination: %w", err)
	}
	parent := filepath.Dir(destination)
	if err := validateRestoreParent(parent); err != nil {
		return Report{}, err
	}
	temporary, err := os.MkdirTemp(parent, "."+filepath.Base(destination)+".restore-")
	if err != nil {
		return Report{}, fmt.Errorf("create Control restore staging directory: %w", err)
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		_ = os.RemoveAll(temporary)
		return Report{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(temporary)
		}
	}()
	report, err = inspect(archivePath, func(file ManifestFile, reader io.Reader) error {
		path := filepath.Join(temporary, file.Name)
		output, err := createExclusive(path, os.FileMode(file.Mode))
		if err != nil {
			return err
		}
		written, copyErr := io.CopyN(output, reader, file.Size)
		if copyErr == nil && written != file.Size {
			copyErr = io.ErrUnexpectedEOF
		}
		if copyErr == nil {
			copyErr = output.Sync()
		}
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		return Report{}, err
	}
	if err := syncDirectory(temporary); err != nil {
		return Report{}, err
	}
	if err := validateRestoredState(temporary, report); err != nil {
		return Report{}, err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return Report{}, fmt.Errorf("publish restored Control state: %w", err)
	}
	keep = true
	if err := syncDirectory(parent); err != nil {
		return Report{}, err
	}
	return report, nil
}

func inspect(archivePath string, consume func(ManifestFile, io.Reader) error) (Report, error) {
	if err := validCleanAbsolute(archivePath, false); err != nil {
		return Report{}, fmt.Errorf("Control backup archive: %w", err)
	}
	archive, info, err := openRegular(archivePath, maxArchiveBytes, 0o600, 0o600)
	if err != nil {
		return Report{}, fmt.Errorf("open Control backup: %w", err)
	}
	defer archive.Close()
	hash := sha256.New()
	limited := &io.LimitedReader{R: archive, N: maxArchiveBytes + 1}
	hashed := io.TeeReader(limited, hash)
	tarReader := tar.NewReader(hashed)
	header, err := tarReader.Next()
	if err != nil || !validTarHeader(header, manifestName, 0o600, maxManifestBytes) {
		return Report{}, errors.New("Control backup manifest entry is invalid")
	}
	manifestRaw, err := io.ReadAll(io.LimitReader(tarReader, maxManifestBytes+1))
	if err != nil || int64(len(manifestRaw)) != header.Size || len(manifestRaw) > maxManifestBytes {
		return Report{}, errors.New("Control backup manifest body is invalid")
	}
	var manifest Manifest
	if err := decodeStrict(manifestRaw, &manifest); err != nil {
		return Report{}, fmt.Errorf("decode Control backup manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return Report{}, err
	}
	for _, expected := range manifest.Files {
		header, err := tarReader.Next()
		if err != nil || !validTarHeader(header, payloadPrefix+expected.Name, os.FileMode(expected.Mode), expected.Size) ||
			header.Size != expected.Size {
			return Report{}, fmt.Errorf("Control backup entry %q is invalid", expected.Name)
		}
		entryHash := sha256.New()
		reader := io.TeeReader(tarReader, entryHash)
		if consume != nil {
			if err := consume(expected, reader); err != nil {
				return Report{}, fmt.Errorf("restore Control backup entry %q: %w", expected.Name, err)
			}
		} else if _, err := io.Copy(io.Discard, reader); err != nil {
			return Report{}, fmt.Errorf("read Control backup entry %q: %w", expected.Name, err)
		}
		if digest(entryHash.Sum(nil)) != expected.SHA256 {
			return Report{}, fmt.Errorf("Control backup entry %q does not match its digest", expected.Name)
		}
	}
	if header, err := tarReader.Next(); err != io.EOF || header != nil {
		return Report{}, errors.New("Control backup contains an undeclared trailing entry")
	}
	if trailing, err := io.ReadAll(hashed); err != nil || len(trailing) != 0 {
		return Report{}, errors.New("Control backup contains bytes after the canonical tar terminator")
	}
	if current, err := archive.Stat(); err != nil || !sameFile(info, current) {
		return Report{}, errors.New("Control backup changed while being read")
	}
	return reportFromManifest(manifest, digest(hash.Sum(nil))), nil
}

func openStateFiles(directory string) ([]openedFile, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read Control state directory: %w", err)
	}
	if len(entries) == 0 || len(entries) > maxFiles+1 {
		return nil, errors.New("Control state file inventory exceeds its limit")
	}
	files := make([]openedFile, 0, len(entries))
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		if name == "LOCK" {
			continue
		}
		if !validStateName(name) {
			closeOpened(files)
			return nil, fmt.Errorf("Control state entry %q has an unsafe name", name)
		}
		file, info, err := openRegular(filepath.Join(directory, name), maxFileBytes, 0o600, 0o644)
		if err != nil {
			closeOpened(files)
			return nil, fmt.Errorf("open Control state entry %q: %w", name, err)
		}
		hash := sha256.New()
		read, readErr := io.Copy(hash, file)
		if readErr != nil || read != info.Size() {
			_ = file.Close()
			closeOpened(files)
			return nil, fmt.Errorf("hash Control state entry %q: %w", name, readErr)
		}
		total += info.Size()
		if total > maxPayloadBytes {
			_ = file.Close()
			closeOpened(files)
			return nil, errors.New("Control state payload exceeds its backup limit")
		}
		files = append(files, openedFile{
			manifest: ManifestFile{Name: name, Size: info.Size(), Mode: uint32(info.Mode().Perm()), SHA256: digest(hash.Sum(nil))},
			file:     file, before: info,
		})
	}
	slices.SortFunc(files, func(left, right openedFile) int { return strings.Compare(left.manifest.Name, right.manifest.Name) })
	return files, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaV1 || manifest.Generation == 0 || manifest.Files == nil ||
		len(manifest.Files) == 0 || len(manifest.Files) > maxFiles {
		return errors.New("Control backup manifest identity or inventory is invalid")
	}
	created, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt)
	if err != nil || created.IsZero() || created.Format(time.RFC3339Nano) != manifest.CreatedAt {
		return errors.New("Control backup creation time is invalid")
	}
	var total int64
	names := make([]string, 0, len(manifest.Files))
	for index, file := range manifest.Files {
		if !validStateName(file.Name) || file.Size < 0 || file.Size > maxFileBytes ||
			(file.Mode != 0o600 && file.Mode != 0o644) || !validDigest(file.SHA256) ||
			index > 0 && manifest.Files[index-1].Name >= file.Name {
			return errors.New("Control backup manifest file is invalid or not canonical")
		}
		total += file.Size
		if total > maxPayloadBytes {
			return errors.New("Control backup payload exceeds its limit")
		}
		names = append(names, file.Name)
	}
	for _, required := range append([]string{"CURRENT"}, requiredIdentityFiles...) {
		if !slices.Contains(names, required) {
			return fmt.Errorf("Control backup omits required file %q", required)
		}
	}
	return nil
}

func validateRestoredState(directory string, report Report) error {
	if err := validateDefaultIdentitySet(directory); err != nil {
		return err
	}
	store, err := controlstore.Open(directory, controlstore.DefaultLimits())
	if err != nil {
		return fmt.Errorf("validate restored Control state: %w", err)
	}
	status, statusErr := store.Status()
	closeErr := store.Close()
	if statusErr != nil {
		return statusErr
	}
	if closeErr != nil {
		return closeErr
	}
	if status.Generation != report.Generation || status.Sequence != report.Sequence {
		return errors.New("restored Control state does not match the backup checkpoint")
	}
	return nil
}

func validateDefaultIdentitySet(directory string) error {
	if _, err := controlauth.LoadKey(filepath.Join(directory, "auth.key")); err != nil {
		return fmt.Errorf("validate backed-up Control authentication identity: %w", err)
	}
	witnessPrivate, witnessPublic, err := controlwitness.LoadPair(
		filepath.Join(directory, "witness.private.pem"), filepath.Join(directory, "witness.public.pem"),
	)
	if err != nil {
		return fmt.Errorf("validate backed-up witness identity: %w", err)
	}
	_, controllerPublic, err := controlwitness.LoadPair(
		filepath.Join(directory, "controller.private.pem"), filepath.Join(directory, "controller.public.pem"),
	)
	if err != nil {
		return fmt.Errorf("validate backed-up controller identity: %w", err)
	}
	if bytes.Equal(witnessPublic, controllerPublic) || len(witnessPrivate) == 0 {
		return errors.New("Control backup requires separate controller and witness identities")
	}
	return nil
}

func openRegular(path string, limit int64, allowedModes ...os.FileMode) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nil, errors.New("open returned an invalid file")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit || linkCount(info) != 1 {
		_ = file.Close()
		return nil, nil, errors.New("file must be bounded, regular, and have one link")
	}
	if !slices.Contains(allowedModes, info.Mode().Perm()) {
		_ = file.Close()
		return nil, nil, errors.New("file mode is not allowed")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		_ = file.Close()
		return nil, nil, errors.New("file must be owned by the current user")
	}
	return file, info, nil
}

func createExclusive(path string, mode os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("create returned an invalid file")
	}
	return file, nil
}

func writeTarEntry(writer *tar.Writer, name string, mode os.FileMode, raw []byte) error {
	header := &tar.Header{Name: name, Mode: int64(mode.Perm()), Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err := writer.Write(raw)
	return err
}

func validTarHeader(header *tar.Header, name string, mode os.FileMode, size int64) bool {
	return header != nil && header.Name == name && header.Typeflag == tar.TypeReg && header.Mode == int64(mode.Perm()) &&
		header.Size >= 0 && header.Size <= size && header.Linkname == "" && header.PAXRecords == nil &&
		header.Uid == 0 && header.Gid == 0 && header.Uname == "" && header.Gname == "" &&
		header.Devmajor == 0 && header.Devminor == 0 && header.Format == tar.FormatUSTAR
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func reportFromManifest(manifest Manifest, archiveDigest string) Report {
	var total int64
	for _, file := range manifest.Files {
		total += file.Size
	}
	return Report{
		SchemaVersion: ReportSchemaV1, Status: "verified", ArchiveSHA256: archiveDigest,
		CreatedAt: manifest.CreatedAt, Generation: manifest.Generation, Sequence: manifest.Sequence,
		Files: len(manifest.Files), PayloadBytes: total,
	}
}

func validateRestoreParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Control restore parent: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || int(stat.Uid) != os.Geteuid() {
		return errors.New("Control restore parent must be a current-user-owned directory not writable by group or others")
	}
	return nil
}

func validCleanAbsolute(path string, allowRoot bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') ||
		(!allowRoot && path == string(filepath.Separator)) {
		return errors.New("path must be clean, absolute, and non-root")
	}
	return nil
}

func pathInside(directory, path string) (bool, error) {
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return false, err
	}
	return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)), nil
}

func validStateName(name string) bool {
	if name == "" || name == "." || name == ".." || name == "LOCK" || len(name) > 128 || filepath.Base(name) != name {
		return false
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func digest(raw []byte) string { return "sha256:" + hex.EncodeToString(raw) }

func closeOpened(files []openedFile) {
	for _, file := range files {
		_ = file.file.Close()
	}
}

func sameFile(before, after os.FileInfo) bool {
	if before == nil || after == nil || before.Size() != after.Size() || before.Mode() != after.Mode() ||
		!before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, after) {
		return false
	}
	return true
}

func linkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
