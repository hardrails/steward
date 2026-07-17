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
	"strconv"
	"strings"
	"syscall"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	// ManifestSchemaV1 identifies the first non-secret materialization manifest.
	ManifestSchemaV1 = "steward.secret-materialization.v1"
	// ManifestSchemaV2 requires an expected provider-version marker for every materialization.
	ManifestSchemaV2 = "steward.secret-materialization.v2"
	// ReportSchemaV1 identifies the corresponding secret-free readiness report.
	ReportSchemaV1 = "steward.secret-materialization-report.v1"
	// ReportSchemaV2 identifies epoch-aware secret-free readiness.
	ReportSchemaV2 = "steward.secret-materialization-report.v2"

	maxManifestBytes = 1 << 20
	maxBindings      = 512
	minSecretBytes   = 12
	maxSecretBytes   = int64(16 << 10)
	maxEpochBytes    = int64(20)
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
	TenantID      string  `json:"tenant_id"`
	SecretID      string  `json:"secret_id"`
	Purpose       Purpose `json:"purpose"`
	ExpectedEpoch uint64  `json:"expected_epoch,omitempty"`
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
	TenantID      string  `json:"tenant_id"`
	SecretID      string  `json:"secret_id"`
	Purpose       Purpose `json:"purpose"`
	ExpectedEpoch uint64  `json:"expected_epoch,omitempty"`
	ObservedEpoch uint64  `json:"observed_epoch,omitempty"`
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
	if (m.SchemaVersion != ManifestSchemaV1 && m.SchemaVersion != ManifestSchemaV2) || len(m.Bindings) == 0 || len(m.Bindings) > maxBindings {
		return fmt.Errorf("secret materialization manifest requires schema %q or %q and 1 through %d bindings", ManifestSchemaV1, ManifestSchemaV2, maxBindings)
	}
	seen := make(map[string]struct{}, len(m.Bindings))
	for index, binding := range m.Bindings {
		if !identifierPattern.MatchString(binding.TenantID) || !identifierPattern.MatchString(binding.SecretID) ||
			(binding.Purpose != PurposeInference && binding.Purpose != PurposeConnector) {
			return fmt.Errorf("secret materialization binding %d has an invalid tenant, secret, or purpose", index)
		}
		if (m.SchemaVersion == ManifestSchemaV1 && binding.ExpectedEpoch != 0) ||
			(m.SchemaVersion == ManifestSchemaV2 && binding.ExpectedEpoch == 0) {
			return fmt.Errorf("secret materialization binding %d has an invalid expected epoch for schema %q", index, m.SchemaVersion)
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
	if manifest.SchemaVersion == ManifestSchemaV2 {
		return Report{}, errors.New("epoch-aware materialization requires a status root")
	}
	return checkSecrets(rootPath, manifest)
}

// CheckWithStatus validates secret values and stable provider-version markers.
// Epochs are non-secret rotation metadata; secret bytes remain excluded from
// the report and are cleared immediately after validation.
func CheckWithStatus(rootPath, statusRootPath string, manifest Manifest) (Report, error) {
	if manifest.SchemaVersion != ManifestSchemaV2 {
		return Report{}, fmt.Errorf("status checking requires schema %q", ManifestSchemaV2)
	}
	if rootPath == statusRootPath {
		return Report{}, errors.New("secret and status roots must be distinct")
	}
	report, err := checkSecrets(rootPath, manifest)
	if err != nil {
		return Report{}, err
	}
	report.SchemaVersion = ReportSchemaV2
	return checkEpochs(statusRootPath, manifest, report)
}

func checkSecrets(rootPath string, manifest Manifest) (Report, error) {
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
		report.Bindings = append(report.Bindings, BindingReport{
			TenantID: binding.TenantID, SecretID: binding.SecretID, Purpose: binding.Purpose,
		})
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

// Prepare creates only deterministic tenant directories below already-existing,
// caller-owned mode-0700 roots. It never creates or changes a secret, epoch, or
// root directory and refuses an existing unsafe tenant boundary.
func Prepare(rootPath, statusRootPath string, manifest Manifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if manifest.SchemaVersion != ManifestSchemaV2 || rootPath == statusRootPath {
		return errors.New("materialization preparation requires schema v2 and distinct roots")
	}
	for _, rootPath := range []string{rootPath, statusRootPath} {
		if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || strings.ContainsRune(rootPath, '\x00') {
			return errors.New("materialization roots must be clean absolute paths")
		}
		owner := uint32(os.Geteuid())
		before, err := os.Lstat(rootPath)
		if err != nil || !validOwnedDirectory(before, owner) {
			return fmt.Errorf("materialization root %q must already be caller-owned, non-symlink, and mode 0700", rootPath)
		}
		device, ok := filesystemDevice(before)
		if !ok {
			return fmt.Errorf("materialization root %q has unsupported filesystem metadata", rootPath)
		}
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			return fmt.Errorf("open materialization root %q: %w", rootPath, err)
		}
		seen := make(map[string]struct{})
		for _, binding := range manifest.Bindings {
			if _, exists := seen[binding.TenantID]; exists {
				continue
			}
			seen[binding.TenantID] = struct{}{}
			if err := root.Mkdir(binding.TenantID, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				root.Close()
				return fmt.Errorf("create tenant materialization directory %q: %w", binding.TenantID, err)
			}
			info, err := root.Lstat(binding.TenantID)
			if err != nil || !validOwnedDirectory(info, owner) || !sameFilesystem(info, device) {
				root.Close()
				return fmt.Errorf("tenant materialization directory %q is unsafe", binding.TenantID)
			}
		}
		root.Close()
		after, err := os.Lstat(rootPath)
		if err != nil || !sameOwnedDirectoryIdentity(before, after, owner) {
			return fmt.Errorf("materialization root %q changed while preparing", rootPath)
		}
	}
	return nil
}

func checkEpochs(statusRootPath string, manifest Manifest, report Report) (Report, error) {
	if !filepath.IsAbs(statusRootPath) || filepath.Clean(statusRootPath) != statusRootPath || strings.ContainsRune(statusRootPath, '\x00') {
		return Report{}, errors.New("secret materialization status root must be a clean absolute path")
	}
	owner := uint32(os.Geteuid())
	rootBefore, err := os.Lstat(statusRootPath)
	if err != nil || !validOwnedDirectory(rootBefore, owner) {
		return Report{}, errors.New("secret materialization status root must be caller-owned, non-symlink, and mode 0700")
	}
	rootDevice, ok := filesystemDevice(rootBefore)
	if !ok {
		return Report{}, errors.New("secret materialization status root has unsupported filesystem metadata")
	}
	root, err := os.OpenRoot(statusRootPath)
	if err != nil {
		return Report{}, fmt.Errorf("open secret materialization status root: %w", err)
	}
	defer root.Close()
	rootOpened, err := root.Stat(".")
	if err != nil || !sameOwnedDirectory(rootBefore, rootOpened, owner) {
		return Report{}, errors.New("secret materialization status root changed while opening")
	}
	tenantDirectories := make(map[string]os.FileInfo)
	markerFiles := make([]os.FileInfo, 0, len(manifest.Bindings))
	for index, binding := range manifest.Bindings {
		tenantBefore, exists := tenantDirectories[binding.TenantID]
		if !exists {
			tenantBefore, err = root.Lstat(binding.TenantID)
			if err != nil || !validOwnedDirectory(tenantBefore, owner) || !sameFilesystem(tenantBefore, rootDevice) {
				return Report{}, fmt.Errorf("tenant status directory %q must be caller-owned, non-symlink, mode 0700, and on the status filesystem", binding.TenantID)
			}
			tenantDirectories[binding.TenantID] = tenantBefore
		}
		tenantRoot, err := root.OpenRoot(binding.TenantID)
		if err != nil {
			return Report{}, fmt.Errorf("open tenant status directory %q: %w", binding.TenantID, err)
		}
		tenantOpened, statErr := tenantRoot.Stat(".")
		if statErr != nil || !sameOwnedDirectory(tenantBefore, tenantOpened, owner) {
			tenantRoot.Close()
			return Report{}, fmt.Errorf("tenant status directory %q changed while opening", binding.TenantID)
		}
		name := binding.SecretID + ".epoch"
		before, err := tenantRoot.Lstat(name)
		if err != nil || !validOwnedEpoch(before, owner) || !sameFilesystem(before, rootDevice) {
			tenantRoot.Close()
			return Report{}, fmt.Errorf("materialization epoch %q/%q must be caller-owned, single-link, regular, mode 0600, and canonical decimal", binding.TenantID, name)
		}
		for _, prior := range markerFiles {
			if os.SameFile(prior, before) {
				tenantRoot.Close()
				return Report{}, fmt.Errorf("materialization epoch %q/%q aliases another binding", binding.TenantID, name)
			}
		}
		raw, err := securefile.ReadRoot(tenantRoot, name, maxEpochBytes, securefile.OwnerOnly)
		if err != nil {
			tenantRoot.Close()
			return Report{}, fmt.Errorf("read materialization epoch %q/%q: %w", binding.TenantID, name, err)
		}
		epochText := string(raw)
		observed, parseErr := strconv.ParseUint(epochText, 10, 64)
		for rawIndex := range raw {
			raw[rawIndex] = 0
		}
		after, statErr := tenantRoot.Lstat(name)
		tenantRoot.Close()
		if parseErr != nil || observed == 0 || strconv.FormatUint(observed, 10) != epochText {
			return Report{}, fmt.Errorf("materialization epoch %q/%q is not canonical positive decimal", binding.TenantID, name)
		}
		if statErr != nil || !sameOwnedEpoch(before, after, owner) {
			return Report{}, fmt.Errorf("materialization epoch %q/%q changed while checking", binding.TenantID, name)
		}
		markerFiles = append(markerFiles, after)
		report.Bindings[index].ExpectedEpoch = binding.ExpectedEpoch
		report.Bindings[index].ObservedEpoch = observed
		if observed != binding.ExpectedEpoch {
			report.Ready = false
		}
	}
	for tenantID, before := range tenantDirectories {
		after, err := root.Lstat(tenantID)
		if err != nil || !sameOwnedDirectory(before, after, owner) {
			return Report{}, fmt.Errorf("tenant status directory %q changed while checking", tenantID)
		}
	}
	rootCurrent, err := os.Lstat(statusRootPath)
	if err != nil || !sameOwnedDirectory(rootBefore, rootCurrent, owner) {
		return Report{}, errors.New("secret materialization status root changed while checking")
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

func sameOwnedDirectoryIdentity(before, after os.FileInfo, owner uint32) bool {
	return validOwnedDirectory(before, owner) && validOwnedDirectory(after, owner) &&
		os.SameFile(before, after) && before.Mode() == after.Mode()
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

func validOwnedEpoch(info os.FileInfo, owner uint32) bool {
	uid, links, ok := unixMetadata(info)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && uid == owner && links == 1 &&
		info.Size() >= 1 && info.Size() <= maxEpochBytes
}

func sameOwnedEpoch(before, after os.FileInfo, owner uint32) bool {
	return validOwnedEpoch(before, owner) && validOwnedEpoch(after, owner) && os.SameFile(before, after) &&
		before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
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
