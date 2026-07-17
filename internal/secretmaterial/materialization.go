// Package secretmaterial validates the provider-neutral filesystem handoff
// between a secret materializer and Steward Gateway. It reads each value only
// for validation, clears that buffer, and never persists, returns, hashes, or
// reports secret values or secret-derived metadata.
package secretmaterial

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	// ManifestSchemaV1 identifies the first non-secret materialization manifest.
	ManifestSchemaV1 = "steward.secret-materialization.v1"
	// ReportSchemaV1 identifies the corresponding secret-free readiness report.
	ReportSchemaV1 = "steward.secret-materialization-report.v1"

	maxManifestBytes = 1 << 20
	maxBindings      = 512
	minSecretBytes   = 12
	maxSecretBytes   = int64(16 << 10)
)

// Purpose is the complete initial vocabulary of secrets consumed by Gateway.
// Workload injection is deliberately not a purpose.
type Purpose string

const (
	PurposeInference Purpose = "inference"
	PurposeConnector Purpose = "connector"
)

// Manifest describes only secret identity and purpose. A
// binding's materialized path is deterministic: <root>/<tenant_id>/<secret_id>.
type Manifest struct {
	SchemaVersion string    `json:"schema_version"`
	Bindings      []Binding `json:"bindings"`
}

// Binding names one Gateway-only secret without containing its value, source,
// provider token, provider-specific path, or an unenforced rotation claim.
type Binding struct {
	TenantID string  `json:"tenant_id"`
	SecretID string  `json:"secret_id"`
	Purpose  Purpose `json:"purpose"`
}

// Report intentionally excludes secret bytes, hashes, provider references, and
// filesystem paths. Tenant and secret identifiers remain sensitive metadata
// that operators may need to protect.
type Report struct {
	SchemaVersion string          `json:"schema_version"`
	Ready         bool            `json:"ready"`
	Bindings      []BindingReport `json:"bindings"`
}

// BindingReport identifies a point-in-time validated materialization.
type BindingReport struct {
	TenantID string  `json:"tenant_id"`
	SecretID string  `json:"secret_id"`
	Purpose  Purpose `json:"purpose"`
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// LoadManifest reads a bounded, non-secret, strictly decoded manifest. The file
// may be group-readable but may not be writable by group or other users.
func LoadManifest(path string) (Manifest, error) {
	raw, err := securefile.Read(path, maxManifestBytes, securefile.TrustFile)
	if err != nil {
		return Manifest{}, fmt.Errorf("read secret materialization manifest: %w", err)
	}
	var manifest Manifest
	if err := dsse.DecodeStrictInto(raw, maxManifestBytes, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode secret materialization manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate checks the complete non-secret manifest contract.
func (m Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaV1 || len(m.Bindings) == 0 || len(m.Bindings) > maxBindings {
		return fmt.Errorf("secret materialization manifest requires schema %q and 1 through %d bindings", ManifestSchemaV1, maxBindings)
	}
	seen := make(map[string]struct{}, len(m.Bindings))
	for index, binding := range m.Bindings {
		if !identifierPattern.MatchString(binding.TenantID) || !identifierPattern.MatchString(binding.SecretID) ||
			(binding.Purpose != PurposeInference && binding.Purpose != PurposeConnector) {
			return fmt.Errorf("secret materialization binding %d has an invalid tenant, secret, or purpose", index)
		}
		identity := binding.TenantID + "\x00" + binding.SecretID
		if _, duplicate := seen[identity]; duplicate {
			return fmt.Errorf("duplicate secret materialization binding %q/%q", binding.TenantID, binding.SecretID)
		}
		seen[identity] = struct{}{}
	}
	return nil
}

// Check verifies a deterministic materialization tree owned by the caller:
// root and tenant directories are exact mode 0700, while each secret is a
// stable, single-link, exact mode 0600 regular file containing one bounded
// visible-ASCII value. The returned report contains no secret-derived value.
func Check(rootPath string, manifest Manifest) (Report, error) {
	if err := manifest.Validate(); err != nil {
		return Report{}, err
	}
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || strings.ContainsRune(rootPath, '\x00') {
		return Report{}, errors.New("secret materialization root must be a clean absolute path")
	}
	owner := uint32(os.Geteuid())
	rootBefore, err := os.Lstat(rootPath)
	if err != nil {
		return Report{}, fmt.Errorf("inspect secret materialization root: %w", err)
	}
	if !validOwnedDirectory(rootBefore, owner) {
		return Report{}, errors.New("secret materialization root must be caller-owned, non-symlink, and mode 0700")
	}
	rootDevice, ok := filesystemDevice(rootBefore)
	if !ok {
		return Report{}, errors.New("secret materialization root has unsupported filesystem metadata")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return Report{}, fmt.Errorf("open secret materialization root: %w", err)
	}
	defer root.Close()
	rootOpened, err := root.Stat(".")
	if err != nil || !sameOwnedDirectory(rootBefore, rootOpened, owner) {
		return Report{}, errors.New("secret materialization root changed while opening")
	}

	tenantDirectories := make(map[string]os.FileInfo)
	materializedFiles := make([]os.FileInfo, 0, len(manifest.Bindings))
	report := Report{SchemaVersion: ReportSchemaV1, Ready: true, Bindings: make([]BindingReport, 0, len(manifest.Bindings))}
	for _, binding := range manifest.Bindings {
		tenantBefore, exists := tenantDirectories[binding.TenantID]
		if !exists {
			tenantBefore, err = root.Lstat(binding.TenantID)
			if err != nil {
				return Report{}, fmt.Errorf("inspect tenant secret directory %q: %w", binding.TenantID, err)
			}
			if !validOwnedDirectory(tenantBefore, owner) || !sameFilesystem(tenantBefore, rootDevice) {
				return Report{}, fmt.Errorf("tenant secret directory %q must be caller-owned, non-symlink, mode 0700, and on the materialization filesystem", binding.TenantID)
			}
			tenantDirectories[binding.TenantID] = tenantBefore
		}
		tenantRoot, err := root.OpenRoot(binding.TenantID)
		if err != nil {
			return Report{}, fmt.Errorf("open tenant secret directory %q: %w", binding.TenantID, err)
		}
		tenantOpened, statErr := tenantRoot.Stat(".")
		if statErr != nil || !sameOwnedDirectory(tenantBefore, tenantOpened, owner) {
			tenantRoot.Close()
			return Report{}, fmt.Errorf("tenant secret directory %q changed while opening", binding.TenantID)
		}

		fileBefore, err := tenantRoot.Lstat(binding.SecretID)
		if err != nil {
			tenantRoot.Close()
			return Report{}, fmt.Errorf("inspect materialized secret %q/%q: %w", binding.TenantID, binding.SecretID, err)
		}
		if !validOwnedSecret(fileBefore, owner) || !sameFilesystem(fileBefore, rootDevice) {
			tenantRoot.Close()
			return Report{}, fmt.Errorf("materialized secret %q/%q must be caller-owned, single-link, regular, mode 0600, and 12 through 16384 bytes", binding.TenantID, binding.SecretID)
		}
		for _, prior := range materializedFiles {
			if os.SameFile(prior, fileBefore) {
				tenantRoot.Close()
				return Report{}, fmt.Errorf("materialized secret %q/%q aliases another binding", binding.TenantID, binding.SecretID)
			}
		}

		raw, err := securefile.ReadRoot(tenantRoot, binding.SecretID, maxSecretBytes, securefile.OwnerOnly)
		if err != nil {
			tenantRoot.Close()
			return Report{}, fmt.Errorf("read materialized secret %q/%q: %w", binding.TenantID, binding.SecretID, err)
		}
		valueErr := validateVisibleSecret(raw)
		for index := range raw {
			raw[index] = 0
		}
		fileAfter, statErr := tenantRoot.Lstat(binding.SecretID)
		tenantRoot.Close()
		if valueErr != nil {
			return Report{}, fmt.Errorf("materialized secret %q/%q: %w", binding.TenantID, binding.SecretID, valueErr)
		}
		if statErr != nil || !sameOwnedSecret(fileBefore, fileAfter, owner) {
			return Report{}, fmt.Errorf("materialized secret %q/%q changed while checking", binding.TenantID, binding.SecretID)
		}
		materializedFiles = append(materializedFiles, fileAfter)
		report.Bindings = append(report.Bindings, BindingReport(binding))
	}

	for tenantID, before := range tenantDirectories {
		after, err := root.Lstat(tenantID)
		if err != nil || !sameOwnedDirectory(before, after, owner) {
			return Report{}, fmt.Errorf("tenant secret directory %q changed while checking", tenantID)
		}
	}
	rootCurrent, err := os.Lstat(rootPath)
	if err != nil || !sameOwnedDirectory(rootBefore, rootCurrent, owner) {
		return Report{}, errors.New("secret materialization root changed while checking")
	}
	return report, nil
}

func validateVisibleSecret(raw []byte) error {
	if len(raw) < minSecretBytes || int64(len(raw)) > maxSecretBytes {
		return errors.New("value must contain 12 through 16384 visible ASCII bytes")
	}
	for _, value := range raw {
		if value < 0x21 || value > 0x7e {
			return errors.New("value must contain exactly one visible ASCII line without surrounding whitespace")
		}
	}
	return nil
}

func validOwnedDirectory(info os.FileInfo, owner uint32) bool {
	uid, _, ok := unixMetadata(info)
	return ok && info.IsDir() && info.Mode().Perm() == 0o700 && uid == owner
}

func sameOwnedDirectory(before, after os.FileInfo, owner uint32) bool {
	return validOwnedDirectory(before, owner) && validOwnedDirectory(after, owner) &&
		os.SameFile(before, after) && before.Mode() == after.Mode() && before.ModTime().Equal(after.ModTime())
}

func validOwnedSecret(info os.FileInfo, owner uint32) bool {
	uid, links, ok := unixMetadata(info)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && uid == owner && links == 1 &&
		info.Size() >= minSecretBytes && info.Size() <= maxSecretBytes
}

func sameOwnedSecret(before, after os.FileInfo, owner uint32) bool {
	return validOwnedSecret(before, owner) && validOwnedSecret(after, owner) &&
		os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime())
}

func unixMetadata(info os.FileInfo) (uint32, uint64, bool) {
	if info == nil {
		return 0, 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return stat.Uid, uint64(stat.Nlink), true
}

func filesystemDevice(info os.FileInfo) (uint64, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Dev), true
}

func sameFilesystem(info os.FileInfo, expected uint64) bool {
	device, ok := filesystemDevice(info)
	return ok && device == expected
}
