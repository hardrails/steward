package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	sitePackageSchema      = "steward.site-package.v1"
	sitePackagePayloadType = "application/vnd.steward.site-package.v1+json"
	maxSitePackageFiles    = 32
)

type siteKeyMaterial struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

type sitePackageFile struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Mode           string `json:"mode"`
	Classification string `json:"classification"`
}

type sitePackageInventory struct {
	SchemaVersion string            `json:"schema_version"`
	SiteID        string            `json:"site_id"`
	TenantID      string            `json:"tenant_id"`
	RootKeyID     string            `json:"root_key_id"`
	PolicyDigest  string            `json:"policy_digest"`
	Files         []sitePackageFile `json:"files"`
}

type sitePackageSummary struct {
	Directory        string   `json:"directory,omitempty"`
	SiteID           string   `json:"site_id"`
	TenantID         string   `json:"tenant_id"`
	PolicyDigest     string   `json:"policy_digest,omitempty"`
	RootPublicSHA256 string   `json:"root_public_sha256,omitempty"`
	FileCount        int      `json:"file_count"`
	DryRun           bool     `json:"dry_run,omitempty"`
	Custody          []string `json:"custody"`
	NextSteps        []string `json:"next_steps"`
}

type siteOutput struct {
	path           string
	contents       []byte
	mode           fs.FileMode
	classification string
}

func siteCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("site requires init, verify, or node")
	}
	switch arguments[0] {
	case "init":
		return siteInit(arguments[1:], stdout)
	case "verify":
		return siteVerify(arguments[1:], stdout)
	case "node":
		return siteNodeCommand(arguments[1:], stdout)
	default:
		return errors.New("site requires init, verify, or node")
	}
}

func siteInit(arguments []string, stdout io.Writer) error {
	arguments = sitePositionalLast(arguments)
	flags := flag.NewFlagSet("site init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	siteID := flags.String("site-id", "steward-site", "stable site identity")
	tenantID := flags.String("tenant-id", "default", "initial tenant identity")
	repository := flags.String("repository", "steward.local/agents", "allowed OCI repository")
	serviceID := flags.String("service-id", "agent-api", "initial agent service identity")
	connectorID := flags.String("connector-id", "", "optional first protected connector identity")
	serverNames := flags.String("control-server-names", "localhost,127.0.0.1,::1", "control TLS DNS names and IP addresses")
	authorizedEffects := flags.String("authorized-effects", "required", "required or optional when a connector is configured")
	dryRun := flags.Bool("dry-run", false, "validate and describe outputs without generating keys or files")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("site init requires exactly one output directory")
	}
	if !validOptionalControlIdentifier(*siteID, 128) || *siteID == "" ||
		!validOptionalControlIdentifier(*tenantID, 128) || *tenantID == "" ||
		!validOptionalControlIdentifier(*serviceID, 128) || *serviceID == "" ||
		(*connectorID != "" && !validOptionalControlIdentifier(*connectorID, 128)) {
		return errors.New("site, tenant, service, or connector identity is invalid")
	}
	if *authorizedEffects != admission.AuthorizedEffectsRequired && *authorizedEffects != admission.AuthorizedEffectsOptional {
		return errors.New("authorized effects must be required or optional")
	}
	if !admission.ValidRepositoryName(*repository) {
		return errors.New("repository is not a valid OCI repository name")
	}
	if *connectorID == "" && flagWasVisited(flags, "authorized-effects") {
		return errors.New("-authorized-effects requires -connector-id")
	}
	dnsNames, ipAddresses, ipStrings, err := canonicalControlPKIServerNames(*serverNames)
	if err != nil {
		return err
	}
	directory, err := filepath.Abs(flags.Arg(0))
	if err != nil || directory == string(filepath.Separator) {
		return errors.New("site output directory is invalid")
	}
	if *dryRun {
		return writeSiteSummary(stdout, sitePackageSummary{
			Directory: directory, SiteID: *siteID, TenantID: *tenantID, DryRun: true,
			FileCount: expectedSiteFileCount(*connectorID != ""), Custody: siteCustodySummary(),
			NextSteps: siteNextSteps(directory),
		})
	}
	if _, err := os.Lstat(directory); err == nil {
		return fmt.Errorf("site output directory %q already exists", directory)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect site output directory: %w", err)
	}
	parent := filepath.Dir(directory)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create site output parent: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("site output parent must be a real directory that is not group- or world-writable")
	}
	temporary, err := os.MkdirTemp(parent, ".steward-site-")
	if err != nil {
		return fmt.Errorf("reserve site output: %w", err)
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		_ = os.RemoveAll(temporary)
		return fmt.Errorf("protect site output: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()

	outputs, policyDigest, rootDigest, inventory, err := buildSitePackage(
		*siteID, *tenantID, *repository, *serviceID, *connectorID,
		*authorizedEffects, dnsNames, ipAddresses, ipStrings,
	)
	if err != nil {
		return err
	}
	for _, directoryName := range []string{"private", "public"} {
		mode := fs.FileMode(0o755)
		if directoryName == "private" {
			mode = 0o700
		}
		if err := os.Mkdir(filepath.Join(temporary, directoryName), mode); err != nil {
			return fmt.Errorf("create site %s directory: %w", directoryName, err)
		}
		if err := os.Chmod(filepath.Join(temporary, directoryName), mode); err != nil {
			return fmt.Errorf("protect site %s directory: %w", directoryName, err)
		}
	}
	for _, output := range outputs {
		path := filepath.Join(temporary, output.path)
		if err := writeNewFile(path, output.contents, output.mode); err != nil {
			return fmt.Errorf("write site package %s: %w", output.path, err)
		}
		if err := setAndSyncSiteMode(path, output.mode); err != nil {
			return fmt.Errorf("set site package mode %s: %w", output.path, err)
		}
	}
	inventoryPath := filepath.Join(temporary, "inventory.dsse.json")
	if err := writeNewFile(inventoryPath, inventory, 0o644); err != nil {
		return fmt.Errorf("write site package inventory: %w", err)
	}
	if err := setAndSyncSiteMode(inventoryPath, 0o644); err != nil {
		return fmt.Errorf("set site package inventory mode: %w", err)
	}
	root, err := os.Open(temporary)
	if err != nil {
		return fmt.Errorf("open site output directory: %w", err)
	}
	if err := root.Sync(); err != nil {
		_ = root.Close()
		return fmt.Errorf("sync site output directory: %w", err)
	}
	if err := root.Close(); err != nil {
		return fmt.Errorf("close site output directory: %w", err)
	}
	if err := os.Rename(temporary, directory); err != nil {
		return fmt.Errorf("publish site output directory: %w", err)
	}
	if err := syncOutputDirectory(directory); err != nil {
		removeErr := os.RemoveAll(directory)
		cleanupSyncErr := syncOutputDirectory(directory)
		return errors.Join(fmt.Errorf("sync published site output: %w", err), removeErr, cleanupSyncErr)
	}
	committed = true
	return writeSiteSummary(stdout, sitePackageSummary{
		Directory: directory, SiteID: *siteID, TenantID: *tenantID, PolicyDigest: policyDigest,
		RootPublicSHA256: rootDigest, FileCount: len(outputs) + 1, Custody: siteCustodySummary(),
		NextSteps: siteNextSteps(directory),
	})
}

func buildSitePackage(siteID, tenantID, repository, serviceID, connectorID, effectsMode string,
	dnsNames []string, ipAddresses []net.IP, ipStrings []string,
) ([]siteOutput, string, string, []byte, error) {
	keys := make(map[string]siteKeyMaterial)
	for _, name := range []string{"site-root", "publisher", "site-cleanup", "tenant-command", "tenant-task"} {
		key, err := newSiteKey()
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("generate %s key: %w", name, err)
		}
		keys[name] = key
	}
	if connectorID != "" {
		key, err := newSiteKey()
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("generate tenant action key: %w", err)
		}
		keys["tenant-action"] = key
	}

	limits := admission.ResourceLimits{MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128}
	tenant := admission.TenantRule{
		TenantID: tenantID, PublisherKeyIDs: []string{"publisher-1"}, ResourceCeiling: limits,
		ServiceIDs: []string{serviceID},
		CommandKeys: []admission.CommandKey{{
			KeyID: "tenant-command-1", PublicKey: base64.StdEncoding.EncodeToString(keys["tenant-command"].public),
			Operations: []string{"admit", "renew", "start", "stop", "destroy", "read", "purge", "snapshot-state", "clone-state", "delete-snapshot", "activation-canary"},
		}},
		TaskKeys: []admission.TaskKey{{
			KeyID: "tenant-task-1", PublicKey: base64.StdEncoding.EncodeToString(keys["tenant-task"].public),
			ServiceIDs: []string{serviceID},
		}},
	}
	if connectorID != "" {
		tenant.ConnectorIDs = []string{connectorID}
		tenant.AuthorizedEffects = &admission.AuthorizedEffectsPolicy{
			Mode: effectsMode,
			Keys: []admission.ActionKey{{
				KeyID: "tenant-action-1", PublicKey: base64.StdEncoding.EncodeToString(keys["tenant-action"].public),
				ConnectorIDs: []string{connectorID},
			}},
		}
	}
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1, PolicyID: siteID, PolicyEpoch: 1,
		SiteCleanupCommandKeys: []admission.CommandKey{{
			KeyID: "site-cleanup-1", PublicKey: base64.StdEncoding.EncodeToString(keys["site-cleanup"].public),
			Operations: []string{"stop", "destroy", "purge", "delete-snapshot"},
		}},
		Publishers: []admission.PublisherRule{{
			KeyID: "publisher-1", PublicKey: base64.StdEncoding.EncodeToString(keys["publisher"].public),
			AllowedProfiles:     []admission.ProfileRef{{ID: "generic-v1", Version: "v1"}},
			AllowedRepositories: []string{repository}, ResourceCeiling: limits,
		}},
		Tenants: []admission.TenantRule{tenant},
	}
	if err := policy.Validate(); err != nil {
		return nil, "", "", nil, fmt.Errorf("validate generated site policy: %w", err)
	}
	policyPayload, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("encode site policy: %w", err)
	}
	policyEnvelope, err := dsse.Sign(admission.PolicyPayloadType, policyPayload, "site-root-1", keys["site-root"].private)
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("sign site policy: %w", err)
	}
	policyRaw, err := dsse.Marshal(policyEnvelope)
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("encode signed site policy: %w", err)
	}

	pki, _, err := generateControlPKI(dnsNames, ipAddresses, ipStrings, defaultControlPKICAValidity, defaultControlPKIServerValidity, time.Now())
	if err != nil {
		return nil, "", "", nil, err
	}
	outputs := make([]siteOutput, 0, maxSitePackageFiles)
	for _, spec := range []struct {
		name           string
		classification string
	}{
		{name: "site-root", classification: "offline-root"},
		{name: "publisher", classification: "offline-publisher"},
		{name: "site-cleanup", classification: "offline-incident-response"},
		{name: "tenant-command", classification: "tenant-online-signer"},
		{name: "tenant-task", classification: "tenant-online-signer"},
	} {
		privateRaw, err := encodeSitePrivateKey(keys[spec.name].private)
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("encode %s private key: %w", spec.name, err)
		}
		outputs = append(outputs,
			siteOutput{path: "private/" + spec.name + ".private.pem", contents: privateRaw, mode: 0o600, classification: spec.classification},
			siteOutput{path: "public/" + spec.name + ".public", contents: encodeSitePublicKey(keys[spec.name].public), mode: 0o644, classification: "public-trust"},
		)
	}
	if connectorID != "" {
		privateRaw, err := encodeSitePrivateKey(keys["tenant-action"].private)
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("encode tenant action private key: %w", err)
		}
		outputs = append(outputs,
			siteOutput{path: "private/tenant-action.private.pem", contents: privateRaw, mode: 0o600, classification: "tenant-action-approver"},
			siteOutput{path: "public/tenant-action.public", contents: encodeSitePublicKey(keys["tenant-action"].public), mode: 0o644, classification: "public-trust"},
		)
	}
	outputs = append(outputs,
		siteOutput{path: "private/control-ca.private.pem", contents: pki.caKey, mode: 0o600, classification: "offline-control-ca"},
		siteOutput{path: "private/control-server.private.pem", contents: pki.serverKey, mode: 0o600, classification: "control-host-secret"},
		siteOutput{path: "public/control-ca.pem", contents: pki.caCertificate, mode: 0o644, classification: "public-trust"},
		siteOutput{path: "public/control-server.pem", contents: pki.serverCertificate, mode: 0o644, classification: "control-host-public"},
		siteOutput{path: "public/site-policy.json", contents: append(policyPayload, '\n'), mode: 0o644, classification: "public-policy-source"},
		siteOutput{path: "public/site-policy.dsse.json", contents: policyRaw, mode: 0o644, classification: "node-trust"},
	)
	outputs = sortedSiteOutputs(outputs)
	files := make([]sitePackageFile, 0, len(outputs))
	for _, output := range outputs {
		files = append(files, siteOutputDigest(output))
	}
	policyDigest := dsse.Digest(policyRaw)
	inventory := sitePackageInventory{
		SchemaVersion: sitePackageSchema, SiteID: siteID, TenantID: tenantID,
		RootKeyID: "site-root-1", PolicyDigest: policyDigest, Files: files,
	}
	inventoryRaw, err := signSiteInventory(inventory, keys["site-root"].private)
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("sign site inventory: %w", err)
	}
	rootDigest := sha256.Sum256(keys["site-root"].public)
	return outputs, policyDigest, "sha256:" + hex.EncodeToString(rootDigest[:]), inventoryRaw, nil
}

func expectedSiteFileCount(withConnector bool) int {
	count := 17
	if withConnector {
		count += 2
	}
	return count
}

func siteCustodySummary() []string {
	return []string{
		"Move site-root, publisher, cleanup, and control-CA private keys to offline custody.",
		"Keep tenant command and task private keys in the tenant-owned signing service.",
		"Install only public/site-policy.dsse.json, public/site-root.public, and public/control-ca.pem on nodes.",
		"Install the control server certificate and key only on the Control host.",
	}
}

func siteNextSteps(directory string) []string {
	return []string{
		"Verify the package: stewardctl site verify " + directory,
		"Separate the private keys by the custody guidance before enrolling a node.",
		"Install Steward Control with the generated TLS certificate and key.",
		"Create the tenant and node enrollment, then install the public node trust files.",
	}
}

func writeSiteSummary(stdout io.Writer, summary sitePackageSummary) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(summary)
}

func setAndSyncSiteMode(path string, mode fs.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func siteVerify(arguments []string, stdout io.Writer) error {
	arguments = sitePositionalLast(arguments)
	flags := flag.NewFlagSet("site verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	pinnedRoot := flags.String("site-root-public-key", "", "independently pinned site-root public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("site verify requires exactly one package directory")
	}
	directory, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return errors.New("site package directory is invalid")
	}
	verified, err := verifySitePackage(directory, *pinnedRoot)
	if err != nil {
		return err
	}
	return writeSiteSummary(stdout, sitePackageSummary{
		Directory: directory, SiteID: verified.inventory.SiteID, TenantID: verified.inventory.TenantID,
		PolicyDigest: verified.inventory.PolicyDigest, RootPublicSHA256: verified.rootDigest,
		FileCount: len(verified.inventory.Files) + 1, Custody: siteCustodySummary(), NextSteps: siteNextSteps(directory),
	})
}

type verifiedSitePackage struct {
	directory    string
	rootKey      ed25519.PublicKey
	rootDigest   string
	inventory    sitePackageInventory
	policy       admission.SitePolicy
	inventoryRaw []byte
}

func verifySitePackage(directory, pinnedRoot string) (verifiedSitePackage, error) {
	if err := verifySiteDirectoryLayout(directory); err != nil {
		return verifiedSitePackage{}, err
	}
	rootPath := pinnedRoot
	if rootPath == "" {
		rootPath = filepath.Join(directory, "public", "site-root.public")
	}
	rootKey, err := readPublicKey(rootPath)
	if err != nil {
		return verifiedSitePackage{}, fmt.Errorf("read trusted site root: %w", err)
	}
	inventoryRaw, err := securefile.Read(filepath.Join(directory, "inventory.dsse.json"), maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return verifiedSitePackage{}, fmt.Errorf("read site inventory: %w", err)
	}
	payload, _, err := dsse.Verify(inventoryRaw, sitePackagePayloadType, map[string]ed25519.PublicKey{"site-root-1": rootKey})
	if err != nil {
		return verifiedSitePackage{}, fmt.Errorf("verify site inventory: %w", err)
	}
	var inventory sitePackageInventory
	if err := dsse.DecodeStrictInto(payload, maxArtifactBytes, &inventory); err != nil {
		return verifiedSitePackage{}, fmt.Errorf("decode site inventory: %w", err)
	}
	if err := validateSiteInventory(inventory); err != nil {
		return verifiedSitePackage{}, err
	}
	if err := verifySitePackageFiles(directory, inventory.Files); err != nil {
		return verifiedSitePackage{}, err
	}
	policyRaw, err := securefile.Read(filepath.Join(directory, "public", "site-policy.dsse.json"), maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return verifiedSitePackage{}, fmt.Errorf("read site policy: %w", err)
	}
	policyPayload, _, err := dsse.Verify(policyRaw, admission.PolicyPayloadType, map[string]ed25519.PublicKey{"site-root-1": rootKey})
	if err != nil {
		return verifiedSitePackage{}, fmt.Errorf("verify site policy: %w", err)
	}
	var policy admission.SitePolicy
	if err := dsse.DecodeStrictInto(policyPayload, maxArtifactBytes, &policy); err != nil {
		return verifiedSitePackage{}, fmt.Errorf("decode site policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return verifiedSitePackage{}, fmt.Errorf("validate site policy: %w", err)
	}
	if dsse.Digest(policyRaw) != inventory.PolicyDigest || policy.PolicyID != inventory.SiteID || len(policy.Tenants) != 1 || policy.Tenants[0].TenantID != inventory.TenantID {
		return verifiedSitePackage{}, errors.New("site inventory and signed policy identities do not match")
	}
	rootDigest := sha256.Sum256(rootKey)
	return verifiedSitePackage{
		directory: directory, rootKey: rootKey, inventory: inventory, policy: policy,
		rootDigest: "sha256:" + hex.EncodeToString(rootDigest[:]), inventoryRaw: inventoryRaw,
	}, nil
}

func sitePositionalLast(arguments []string) []string {
	if len(arguments) == 0 || strings.HasPrefix(arguments[0], "-") {
		return arguments
	}
	normalized := append([]string(nil), arguments[1:]...)
	return append(normalized, arguments[0])
}

func validateSiteInventory(inventory sitePackageInventory) error {
	if inventory.SchemaVersion != sitePackageSchema || inventory.RootKeyID != "site-root-1" ||
		!validOptionalControlIdentifier(inventory.SiteID, 128) || inventory.SiteID == "" ||
		!validOptionalControlIdentifier(inventory.TenantID, 128) || inventory.TenantID == "" ||
		!validSiteSHA256(inventory.PolicyDigest) || len(inventory.Files) == 0 || len(inventory.Files) > maxSitePackageFiles {
		return errors.New("site inventory identity is invalid")
	}
	previous := ""
	seen := make(map[string]struct{}, len(inventory.Files))
	specs := sitePackageFileSpecifications()
	for _, file := range inventory.Files {
		if file.Path <= previous || filepath.Clean(file.Path) != file.Path || filepath.IsAbs(file.Path) || strings.HasPrefix(file.Path, "..") ||
			(file.Mode != "0600" && file.Mode != "0644") || !validSiteSHA256(file.SHA256) || file.Classification == "" {
			return errors.New("site inventory file entry is invalid")
		}
		spec, ok := specs[file.Path]
		if !ok || file.Mode != fmt.Sprintf("%04o", spec.mode) || file.Classification != spec.classification {
			return fmt.Errorf("site inventory file %q is outside the package contract", file.Path)
		}
		seen[file.Path] = struct{}{}
		previous = file.Path
	}
	for path := range specs {
		_, present := seen[path]
		optional := strings.Contains(path, "tenant-action")
		if !optional && !present {
			return fmt.Errorf("site inventory is missing required file %q", path)
		}
	}
	_, privateAction := seen["private/tenant-action.private.pem"]
	_, publicAction := seen["public/tenant-action.public"]
	if privateAction != publicAction {
		return errors.New("site inventory must contain both tenant action key files or neither")
	}
	return nil
}

type siteFileSpecification struct {
	mode           fs.FileMode
	classification string
}

func sitePackageFileSpecifications() map[string]siteFileSpecification {
	return map[string]siteFileSpecification{
		"private/control-ca.private.pem":     {mode: 0o600, classification: "offline-control-ca"},
		"private/control-server.private.pem": {mode: 0o600, classification: "control-host-secret"},
		"private/publisher.private.pem":      {mode: 0o600, classification: "offline-publisher"},
		"private/site-cleanup.private.pem":   {mode: 0o600, classification: "offline-incident-response"},
		"private/site-root.private.pem":      {mode: 0o600, classification: "offline-root"},
		"private/tenant-action.private.pem":  {mode: 0o600, classification: "tenant-action-approver"},
		"private/tenant-command.private.pem": {mode: 0o600, classification: "tenant-online-signer"},
		"private/tenant-task.private.pem":    {mode: 0o600, classification: "tenant-online-signer"},
		"public/control-ca.pem":              {mode: 0o644, classification: "public-trust"},
		"public/control-server.pem":          {mode: 0o644, classification: "control-host-public"},
		"public/publisher.public":            {mode: 0o644, classification: "public-trust"},
		"public/site-cleanup.public":         {mode: 0o644, classification: "public-trust"},
		"public/site-policy.dsse.json":       {mode: 0o644, classification: "node-trust"},
		"public/site-policy.json":            {mode: 0o644, classification: "public-policy-source"},
		"public/site-root.public":            {mode: 0o644, classification: "public-trust"},
		"public/tenant-action.public":        {mode: 0o644, classification: "public-trust"},
		"public/tenant-command.public":       {mode: 0o644, classification: "public-trust"},
		"public/tenant-task.public":          {mode: 0o644, classification: "public-trust"},
	}
}

func verifySitePackageFiles(directory string, expected []sitePackageFile) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("open site package root: %w", err)
	}
	defer root.Close()

	actual := make(map[string]struct{}, len(expected))
	for _, file := range expected {
		name := filepath.FromSlash(file.Path)
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("site package file %q is missing or not regular", file.Path)
		}
		mode := fmt.Sprintf("%04o", info.Mode().Perm())
		if mode != file.Mode {
			return fmt.Errorf("site package file %q mode is %s, expected %s", file.Path, mode, file.Mode)
		}
		if info.Size() < 0 || info.Size() > maxArtifactBytes {
			return fmt.Errorf("site package file %q exceeds the verification limit", file.Path)
		}
		raw, err := securefile.ReadRootMode(root, name, maxArtifactBytes, info.Mode().Perm())
		if err != nil {
			return fmt.Errorf("read site package file %q: %w", file.Path, err)
		}
		digest := sha256.Sum256(raw)
		if "sha256:"+hex.EncodeToString(digest[:]) != file.SHA256 {
			return fmt.Errorf("site package file %q digest does not match signed inventory", file.Path)
		}
		actual[file.Path] = struct{}{}
	}
	err = filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			relative, err := filepath.Rel(directory, path)
			if err != nil {
				return err
			}
			if relative != "." && relative != "private" && relative != "public" {
				return fmt.Errorf("site package contains unsigned directory %q", filepath.ToSlash(relative))
			}
			return nil
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "inventory.dsse.json" {
			return nil
		}
		if _, ok := actual[relative]; !ok {
			return fmt.Errorf("site package contains unsigned file %q", relative)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func verifySiteDirectoryLayout(directory string) error {
	for _, expected := range []struct {
		path string
		mode fs.FileMode
		dir  bool
	}{
		{path: directory, mode: 0o700, dir: true},
		{path: filepath.Join(directory, "private"), mode: 0o700, dir: true},
		{path: filepath.Join(directory, "public"), mode: 0o755, dir: true},
		{path: filepath.Join(directory, "inventory.dsse.json"), mode: 0o644},
	} {
		info, err := os.Lstat(expected.path)
		if err != nil || expected.dir && !info.IsDir() || !expected.dir && !info.Mode().IsRegular() || info.Mode().Perm() != expected.mode {
			return fmt.Errorf("site package path %q must be a real %s with mode %04o", expected.path, map[bool]string{true: "directory", false: "file"}[expected.dir], expected.mode)
		}
	}
	return nil
}

func validSiteSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func newSiteKey() (siteKeyMaterial, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	return siteKeyMaterial{private: private, public: public}, err
}

func encodeSitePrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

func encodeSitePublicKey(key ed25519.PublicKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(key) + "\n")
}

func siteOutputDigest(output siteOutput) sitePackageFile {
	digest := sha256.Sum256(output.contents)
	return sitePackageFile{
		Path: output.path, SHA256: "sha256:" + hex.EncodeToString(digest[:]),
		Mode: fmt.Sprintf("%04o", output.mode.Perm()), Classification: output.classification,
	}
}

func signSiteInventory(inventory sitePackageInventory, root ed25519.PrivateKey) ([]byte, error) {
	payload, err := json.Marshal(inventory)
	if err != nil {
		return nil, err
	}
	envelope, err := dsse.Sign(sitePackagePayloadType, payload, inventory.RootKeyID, root)
	if err != nil {
		return nil, err
	}
	return dsse.Marshal(envelope)
}

func sortedSiteOutputs(outputs []siteOutput) []siteOutput {
	slices.SortFunc(outputs, func(left, right siteOutput) int { return strings.Compare(left.path, right.path) })
	return outputs
}
