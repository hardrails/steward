package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
)

const siteNodePackageSchema = "steward.site-node-package.v1"

const (
	siteNodeActivationStateSchema    = "steward.site-node-activation-state.v1"
	siteNodeActivationCompleteSchema = "steward.site-node-activation.v1"
)

var siteNodePublicFiles = []string{
	"public/control-ca.pem",
	"public/site-policy.dsse.json",
	"public/site-root.public",
}

type siteNodePackageManifest struct {
	SchemaVersion        string   `json:"schema_version"`
	SiteID               string   `json:"site_id"`
	TenantID             string   `json:"tenant_id"`
	NodeID               string   `json:"node_id"`
	ControlURL           string   `json:"control_url"`
	EnrollmentRequestID  string   `json:"enrollment_request_id"`
	ExchangeRequestID    string   `json:"exchange_request_id"`
	ControllerInstanceID string   `json:"controller_instance_id"`
	EnrollmentID         string   `json:"enrollment_id"`
	EnrollmentExpiresAt  string   `json:"enrollment_expires_at"`
	SiteInventorySHA256  string   `json:"site_inventory_sha256"`
	EnrollmentSHA256     string   `json:"enrollment_sha256"`
	PublicFiles          []string `json:"public_files"`
}

type verifiedSiteNodePackage struct {
	directory      string
	manifest       siteNodePackageManifest
	enrollment     controlclient.Enrollment
	rootKey        ed25519.PublicKey
	rootDigest     string
	manifestDigest string
}

type siteNodeSummary struct {
	Directory            string   `json:"directory"`
	Phase                string   `json:"phase"`
	SiteID               string   `json:"site_id"`
	TenantID             string   `json:"tenant_id"`
	NodeID               string   `json:"node_id"`
	ControllerInstanceID string   `json:"controller_instance_id"`
	EnrollmentID         string   `json:"enrollment_id"`
	EnrollmentExpiresAt  string   `json:"enrollment_expires_at"`
	RootPublicSHA256     string   `json:"root_public_sha256"`
	NextSteps            []string `json:"next_steps"`
}

type siteNodeActivationState struct {
	SchemaVersion         string `json:"schema_version"`
	PackageManifestSHA256 string `json:"package_manifest_sha256"`
	SiteID                string `json:"site_id"`
	TenantID              string `json:"tenant_id"`
	NodeID                string `json:"node_id"`
	ControllerInstanceID  string `json:"controller_instance_id"`
	EnrollmentID          string `json:"enrollment_id"`
	ExchangeRequestID     string `json:"exchange_request_id"`
}

type siteNodeActivationComplete struct {
	SchemaVersion         string            `json:"schema_version"`
	PackageManifestSHA256 string            `json:"package_manifest_sha256"`
	SiteID                string            `json:"site_id"`
	TenantID              string            `json:"tenant_id"`
	NodeID                string            `json:"node_id"`
	ControllerInstanceID  string            `json:"controller_instance_id"`
	EnrollmentID          string            `json:"enrollment_id"`
	CredentialID          string            `json:"credential_id"`
	Files                 []sitePackageFile `json:"files"`
}

type siteNodeActivationSummary struct {
	Directory            string   `json:"directory"`
	Phase                string   `json:"phase"`
	SiteID               string   `json:"site_id"`
	TenantID             string   `json:"tenant_id"`
	NodeID               string   `json:"node_id"`
	ControllerInstanceID string   `json:"controller_instance_id"`
	EnrollmentID         string   `json:"enrollment_id"`
	CredentialID         string   `json:"credential_id"`
	InstallerArguments   []string `json:"installer_arguments"`
}

func siteNodeCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("site node requires prepare, activate, or verify")
	}
	switch arguments[0] {
	case "prepare":
		return siteNodePrepare(arguments[1:], stdout)
	case "activate":
		return siteNodeActivate(arguments[1:], stdout)
	case "verify":
		return siteNodeVerify(arguments[1:], stdout)
	default:
		return errors.New("site node requires prepare, activate, or verify")
	}
}

func siteNodePrepare(arguments []string, stdout io.Writer) error {
	contextual, err := applyCLIContext(append([]string{"enrollment", "create"}, arguments...))
	if err != nil {
		return err
	}
	arguments = siteNodePositionalsLast(contextual[2:], 2)
	flags := flag.NewFlagSet("site node prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	output := flags.String("out", "", "new owner-only node enrollment package")
	requestID := flags.String("request-id", "", "stable enrollment request identity")
	validFor := flags.Duration("valid-for", 30*time.Minute, "one-time enrollment lifetime")
	pinnedRoot := flags.String("site-root-public-key", "", "independently pinned site-root public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 2 {
		return errors.New("site node prepare requires a site package directory and node ID")
	}
	siteDirectory, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return errors.New("site package directory is invalid")
	}
	nodeID := flags.Arg(1)
	if !validOptionalControlIdentifier(nodeID, 128) || nodeID == "" {
		return errors.New("node identity is invalid")
	}
	verified, err := verifySitePackage(siteDirectory, *pinnedRoot)
	if err != nil {
		return err
	}
	if *validFor < time.Second || *validFor > 24*time.Hour || *validFor%time.Second != 0 {
		return errors.New("site node enrollment lifetime must be whole seconds between 1 second and 24 hours")
	}
	if *output == "" {
		*output = filepath.Join(filepath.Dir(siteDirectory), "steward-node-"+nodeID)
	}
	outputDirectory, err := validatedNewPackagePath(*output)
	if err != nil {
		return err
	}
	if *requestID == "" {
		*requestID = derivedSiteNodeRequestID("enroll", verified.inventory.SiteID, nodeID)
	}
	if !validOptionalControlIdentifier(*requestID, 128) || *requestID == "" {
		return errors.New("enrollment request identity is invalid")
	}
	if common.tokenFile == nil || *common.tokenFile == "" {
		return errors.New("site node prepare requires a Control operator token or context")
	}
	if *common.caFile == "" {
		*common.caFile = filepath.Join(siteDirectory, "public", "control-ca.pem")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tenant, err := client.CreateTenant(ctx, verified.inventory.TenantID)
	if err != nil {
		return fmt.Errorf("ensure Control tenant: %w", err)
	}
	if tenant.TenantID != verified.inventory.TenantID || tenant.State != "active" {
		return errors.New("Control returned a tenant outside the signed site identity")
	}
	enrollment, err := client.CreateEnrollment(ctx, *requestID, nodeID, []string{verified.inventory.TenantID}, *validFor)
	if err != nil {
		return fmt.Errorf("create Control enrollment: %w", err)
	}
	if err := validatePreparedEnrollment(enrollment, verified.inventory.TenantID, nodeID); err != nil {
		return err
	}
	enrollmentRaw, err := json.Marshal(enrollment)
	if err != nil {
		return fmt.Errorf("encode enrollment capability: %w", err)
	}
	enrollmentRaw = append(enrollmentRaw, '\n')
	manifest := siteNodePackageManifest{
		SchemaVersion: siteNodePackageSchema, SiteID: verified.inventory.SiteID,
		TenantID: verified.inventory.TenantID, NodeID: nodeID, ControlURL: *common.url,
		EnrollmentRequestID:  *requestID,
		ExchangeRequestID:    derivedSiteNodeRequestID("exchange", verified.inventory.SiteID, nodeID),
		ControllerInstanceID: enrollment.ControllerInstanceID, EnrollmentID: enrollment.EnrollmentID,
		EnrollmentExpiresAt: enrollment.ExpiresAt, SiteInventorySHA256: digestSiteNodeBytes(verified.inventoryRaw),
		EnrollmentSHA256: digestSiteNodeBytes(enrollmentRaw), PublicFiles: slices.Clone(siteNodePublicFiles),
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode node package manifest: %w", err)
	}
	manifestRaw = append(manifestRaw, '\n')
	files, err := siteNodePackageOutputs(verified, manifestRaw, enrollmentRaw)
	if err != nil {
		return err
	}
	if err := publishSiteNodePackage(outputDirectory, files); err != nil {
		return err
	}
	prepared, err := verifySiteNodePackage(outputDirectory, *pinnedRoot)
	if err != nil {
		removeErr := os.RemoveAll(outputDirectory)
		return errors.Join(fmt.Errorf("verify published node package: %w", err), removeErr)
	}
	return writeSiteNodeSummary(stdout, prepared, "prepared")
}

func siteNodeActivate(arguments []string, stdout io.Writer) error {
	arguments = siteNodePositionalsLast(arguments, 1)
	flags := flag.NewFlagSet("site node activate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("out", "", "resumable owner-only node activation directory")
	pinnedRoot := flags.String("site-root-public-key", "", "independently pinned site-root public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("site node activate requires one prepared node package directory")
	}
	packageDirectory, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return errors.New("prepared node package directory is invalid")
	}
	prepared, err := verifySiteNodePackage(packageDirectory, *pinnedRoot)
	if err != nil {
		return err
	}
	expires, _ := time.Parse(time.RFC3339Nano, prepared.enrollment.ExpiresAt)
	if !expires.After(timeNow().Add(5 * time.Second)) {
		return errors.New("node enrollment has expired or is too close to expiry; prepare a new enrollment")
	}
	if *output == "" {
		*output = filepath.Join(filepath.Dir(packageDirectory), "steward-node-"+prepared.manifest.NodeID+"-activation")
	}
	activationDirectory, err := filepath.Abs(*output)
	if err != nil || activationDirectory == string(filepath.Separator) {
		return errors.New("node activation directory is invalid")
	}
	state := siteNodeActivationState{
		SchemaVersion: siteNodeActivationStateSchema, PackageManifestSHA256: prepared.manifestDigest,
		SiteID: prepared.manifest.SiteID, TenantID: prepared.manifest.TenantID, NodeID: prepared.manifest.NodeID,
		ControllerInstanceID: prepared.manifest.ControllerInstanceID, EnrollmentID: prepared.manifest.EnrollmentID,
		ExchangeRequestID: prepared.manifest.ExchangeRequestID,
	}
	privateKey, err := ensureSiteNodeActivationWorkspace(activationDirectory, state)
	if err != nil {
		return err
	}
	if complete, err := readCompletedSiteNodeActivation(activationDirectory, state); err != nil {
		return err
	} else if complete != nil {
		return writeSiteNodeActivationSummary(stdout, activationDirectory, prepared, complete.CredentialID)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		prepared.enrollment.ControllerInstanceID, prepared.enrollment.EnrollmentID,
		prepared.enrollment.NodeID, prepared.enrollment.NodeID, 1, privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		return fmt.Errorf("create Executor evidence identity claim: %w", err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, privateKey)
	if err != nil {
		return fmt.Errorf("sign Executor evidence identity claim: %w", err)
	}
	packageRoot, err := os.OpenRoot(packageDirectory)
	if err != nil {
		return err
	}
	caRaw, err := securefile.ReadRootMode(packageRoot, "public/control-ca.pem", maxArtifactBytes, 0o644)
	if err != nil {
		_ = packageRoot.Close()
		return err
	}
	client, err := controlclient.New(prepared.manifest.ControlURL, "", caRaw)
	if err != nil {
		_ = packageRoot.Close()
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	credential, err := client.Enroll(ctx, prepared.enrollment.EnrollmentToken, state.ExchangeRequestID, proof)
	if err != nil {
		_ = packageRoot.Close()
		return fmt.Errorf("exchange node enrollment: %w; rerun the same command to resume with the retained receipt key", err)
	}
	credentialID, err := validateEnrollmentCredential(prepared.enrollment, credential)
	if err != nil {
		_ = packageRoot.Close()
		return err
	}
	credentialRaw, err := json.Marshal(credential)
	if err != nil {
		_ = packageRoot.Close()
		return err
	}
	credentialRaw = append(credentialRaw, '\n')
	evidenceConfig := fmt.Appendf(nil,
		"STEWARD_EXECUTOR_EVIDENCE_CONFIG_VERSION=1\n"+
			"STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID=%s\n"+
			"STEWARD_EXECUTOR_EVIDENCE_NODE_ID=%s\n"+
			"STEWARD_EXECUTOR_EVIDENCE_RECEIPT_EPOCH=1\n"+
			"STEWARD_EXECUTOR_EVIDENCE_PUBLIC_KEY_BASE64=%s\n",
		prepared.enrollment.ControllerInstanceID, prepared.enrollment.NodeID, claim.PublicKeyBase64,
	)
	activationOutputs := []siteOutput{
		{path: "private/executor-node.json", contents: credentialRaw, mode: 0o600, classification: "node-control-credential"},
		{path: "private/executor-evidence.env", contents: evidenceConfig, mode: 0o600, classification: "node-evidence-enrollment"},
	}
	for _, source := range siteNodePublicFiles {
		raw, readErr := securefile.ReadRootMode(packageRoot, filepath.FromSlash(source), maxArtifactBytes, 0o644)
		if readErr != nil {
			_ = packageRoot.Close()
			return readErr
		}
		target := source
		if source == "public/control-ca.pem" {
			target = "public/control-plane-ca.pem"
		}
		activationOutputs = append(activationOutputs, siteOutput{
			path: target, contents: raw, mode: 0o644, classification: "node-trust",
		})
	}
	if err := packageRoot.Close(); err != nil {
		return err
	}
	for _, output := range activationOutputs {
		if err := writeOrVerifyActivationFile(activationDirectory, output); err != nil {
			return err
		}
	}
	completeFiles, err := activationFileInventory(activationDirectory)
	if err != nil {
		return err
	}
	complete := siteNodeActivationComplete{
		SchemaVersion: siteNodeActivationCompleteSchema, PackageManifestSHA256: prepared.manifestDigest,
		SiteID: state.SiteID, TenantID: state.TenantID, NodeID: state.NodeID,
		ControllerInstanceID: state.ControllerInstanceID, EnrollmentID: state.EnrollmentID,
		CredentialID: credentialID, Files: completeFiles,
	}
	completeRaw, err := json.MarshalIndent(complete, "", "  ")
	if err != nil {
		return err
	}
	completeRaw = append(completeRaw, '\n')
	if err := writeNewFile(filepath.Join(activationDirectory, "activation.json"), completeRaw, 0o600); err != nil {
		return fmt.Errorf("commit node activation: %w", err)
	}
	if err := setAndSyncSiteMode(filepath.Join(activationDirectory, "activation.json"), 0o600); err != nil {
		return err
	}
	if _, err := readCompletedSiteNodeActivation(activationDirectory, state); err != nil {
		return fmt.Errorf("verify completed node activation: %w", err)
	}
	return writeSiteNodeActivationSummary(stdout, activationDirectory, prepared, credentialID)
}

func ensureSiteNodeActivationWorkspace(directory string, state siteNodeActivationState) (ed25519.PrivateKey, error) {
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		if _, err := validatedNewPackagePath(directory); err != nil {
			return nil, err
		}
		key, err := newSiteKey()
		if err != nil {
			return nil, err
		}
		privateRaw, err := encodeSitePrivateKey(key.private)
		if err != nil {
			return nil, err
		}
		stateRaw, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return nil, err
		}
		outputs := []siteOutput{
			{path: "activation-state.json", contents: append(stateRaw, '\n'), mode: 0o600},
			{path: "private/node-receipts.private.pem", contents: privateRaw, mode: 0o600},
			{path: "public/node-receipts.public", contents: encodeSitePublicKey(key.public), mode: 0o644},
		}
		if err := publishSiteNodeActivationWorkspace(directory, outputs); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := verifySiteNodeActivationWorkspace(directory, state); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	privateRaw, err := securefile.ReadRootMode(root, "private/node-receipts.private.pem", maxArtifactBytes, 0o600)
	if err != nil {
		return nil, fmt.Errorf("read retained node receipt key: %w", err)
	}
	privateKey, err := decodePrivateKey(privateRaw)
	if err != nil {
		return nil, fmt.Errorf("decode retained node receipt key: %w", err)
	}
	publicRaw, err := securefile.ReadRootMode(root, "public/node-receipts.public", maxArtifactBytes, 0o644)
	if err != nil {
		return nil, fmt.Errorf("read retained node receipt public key: %w", err)
	}
	publicKey, err := decodePublicKey(publicRaw)
	if err != nil {
		return nil, fmt.Errorf("decode retained node receipt public key: %w", err)
	}
	if !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		return nil, errors.New("node activation receipt key pair does not match")
	}
	return privateKey, nil
}

func publishSiteNodeActivationWorkspace(directory string, outputs []siteOutput) error {
	parent := filepath.Dir(directory)
	temporary, err := os.MkdirTemp(parent, ".steward-node-activation-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(temporary, "private"), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(temporary, "public"), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(temporary, "private"), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(temporary, "public"), 0o755); err != nil {
		return err
	}
	for _, output := range outputs {
		path := filepath.Join(temporary, filepath.FromSlash(output.path))
		if err := writeNewFile(path, output.contents, output.mode); err != nil {
			return err
		}
		if err := setAndSyncSiteMode(path, output.mode); err != nil {
			return err
		}
	}
	if err := os.Rename(temporary, directory); err != nil {
		return err
	}
	if err := syncOutputDirectory(directory); err != nil {
		return err
	}
	committed = true
	return nil
}

func verifySiteNodeActivationWorkspace(directory string, expected siteNodeActivationState) error {
	allowed := map[string]fs.FileMode{
		".": 0o700, "private": 0o700, "public": 0o755,
		"activation-state.json":             0o600,
		"private/node-receipts.private.pem": 0o600,
		"public/node-receipts.public":       0o644,
		"private/executor-node.json":        0o600,
		"private/executor-evidence.env":     0o600,
		"public/control-plane-ca.pem":       0o644,
		"public/site-policy.dsse.json":      0o644,
		"public/site-root.public":           0o644,
		"activation.json":                   0o600,
	}
	required := map[string]bool{
		".": true, "private": true, "public": true, "activation-state.json": true,
		"private/node-receipts.private.pem": true, "public/node-receipts.public": true,
	}
	seen := make(map[string]bool)
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		mode, ok := allowed[relative]
		if !ok {
			return fmt.Errorf("node activation contains unexpected path %q", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		isDirectory := relative == "." || relative == "private" || relative == "public"
		if entry.IsDir() != isDirectory || (!isDirectory && !info.Mode().IsRegular()) || info.Mode().Perm() != mode {
			return fmt.Errorf("node activation path %q has an invalid type or mode", relative)
		}
		seen[relative] = true
		return nil
	})
	if err != nil {
		return err
	}
	for name := range required {
		if !seen[name] {
			return fmt.Errorf("node activation is missing %q", name)
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	raw, err := securefile.ReadRootMode(root, "activation-state.json", maxArtifactBytes, 0o600)
	if err != nil {
		return err
	}
	var retained siteNodeActivationState
	if err := dsse.DecodeStrictInto(raw, maxArtifactBytes, &retained); err != nil {
		return err
	}
	if retained != expected {
		return errors.New("node activation state does not match the prepared package")
	}
	return nil
}

func writeOrVerifyActivationFile(directory string, output siteOutput) error {
	path := filepath.Join(directory, filepath.FromSlash(output.path))
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeNewFile(path, output.contents, output.mode); err != nil {
			return fmt.Errorf("write node activation %s: %w", output.path, err)
		}
		return setAndSyncSiteMode(path, output.mode)
	} else if err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	retained, err := securefile.ReadRootMode(root, filepath.FromSlash(output.path), maxArtifactBytes, output.mode)
	if err != nil {
		return err
	}
	if !slices.Equal(retained, output.contents) {
		return fmt.Errorf("retained node activation file %q differs from the idempotent enrollment result", output.path)
	}
	return nil
}

func activationFileInventory(directory string) ([]sitePackageFile, error) {
	classifications := map[string]string{
		"activation-state.json":             "recovery-state",
		"private/node-receipts.private.pem": "node-evidence-private-key",
		"public/node-receipts.public":       "node-evidence-public-key",
		"private/executor-node.json":        "node-control-credential",
		"private/executor-evidence.env":     "node-evidence-enrollment",
		"public/control-plane-ca.pem":       "node-trust",
		"public/site-policy.dsse.json":      "node-trust",
		"public/site-root.public":           "node-trust",
	}
	names := make([]string, 0, len(classifications))
	for name := range classifications {
		names = append(names, name)
	}
	slices.Sort(names)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	files := make([]sitePackageFile, 0, len(names))
	for _, name := range names {
		mode := fs.FileMode(0o644)
		if strings.HasPrefix(name, "private/") || name == "activation-state.json" {
			mode = 0o600
		}
		raw, err := securefile.ReadRootMode(root, filepath.FromSlash(name), maxArtifactBytes, mode)
		if err != nil {
			return nil, err
		}
		files = append(files, sitePackageFile{
			Path: name, SHA256: digestSiteNodeBytes(raw), Mode: fmt.Sprintf("%04o", mode),
			Classification: classifications[name],
		})
	}
	return files, nil
}

func readCompletedSiteNodeActivation(directory string, expected siteNodeActivationState) (*siteNodeActivationComplete, error) {
	path := filepath.Join(directory, "activation.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	raw, err := securefile.ReadRootMode(root, "activation.json", maxArtifactBytes, 0o600)
	if err != nil {
		return nil, err
	}
	var complete siteNodeActivationComplete
	if err := dsse.DecodeStrictInto(raw, maxArtifactBytes, &complete); err != nil {
		return nil, err
	}
	if complete.SchemaVersion != siteNodeActivationCompleteSchema ||
		complete.PackageManifestSHA256 != expected.PackageManifestSHA256 || complete.SiteID != expected.SiteID ||
		complete.TenantID != expected.TenantID || complete.NodeID != expected.NodeID ||
		complete.ControllerInstanceID != expected.ControllerInstanceID || complete.EnrollmentID != expected.EnrollmentID ||
		complete.CredentialID == "" {
		return nil, errors.New("completed node activation does not match its recovery state")
	}
	files, err := activationFileInventory(directory)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(complete.Files, files) {
		return nil, errors.New("completed node activation files do not match its inventory")
	}
	return &complete, nil
}

func writeSiteNodeActivationSummary(stdout io.Writer, directory string, prepared verifiedSiteNodePackage, credentialID string) error {
	arguments := []string{
		"sudo", "/bin/bash", "-p", "/root/steward-install/install-steward.sh", "--non-interactive",
		"--control-plane-url", prepared.manifest.ControlURL,
		"--executor-credential", filepath.Join(directory, "private", "executor-node.json"),
		"--ca-file", filepath.Join(directory, "public", "control-plane-ca.pem"),
		"--admission-policy", filepath.Join(directory, "public", "site-policy.dsse.json"),
		"--site-root-public-key", filepath.Join(directory, "public", "site-root.public"),
		"--site-root-key-id", "site-root-1", "--node-id", prepared.manifest.NodeID,
		"--executor-evidence-config", filepath.Join(directory, "private", "executor-evidence.env"),
		"--executor-evidence-private-key", filepath.Join(directory, "private", "node-receipts.private.pem"),
		"--executor-evidence-public-key", filepath.Join(directory, "public", "node-receipts.public"),
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(siteNodeActivationSummary{
		Directory: directory, Phase: "ready", SiteID: prepared.manifest.SiteID,
		TenantID: prepared.manifest.TenantID, NodeID: prepared.manifest.NodeID,
		ControllerInstanceID: prepared.manifest.ControllerInstanceID,
		EnrollmentID:         prepared.manifest.EnrollmentID, CredentialID: credentialID,
		InstallerArguments: arguments,
	})
}

func siteNodeVerify(arguments []string, stdout io.Writer) error {
	arguments = siteNodePositionalsLast(arguments, 1)
	flags := flag.NewFlagSet("site node verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	pinnedRoot := flags.String("site-root-public-key", "", "independently pinned site-root public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("site node verify requires one node package directory")
	}
	directory, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return errors.New("site node package directory is invalid")
	}
	verified, err := verifySiteNodePackage(directory, *pinnedRoot)
	if err != nil {
		return err
	}
	return writeSiteNodeSummary(stdout, verified, "verified")
}

func verifySiteNodePackage(directory, pinnedRoot string) (verifiedSiteNodePackage, error) {
	if err := verifyFixedPackageLayout(directory, map[string]fs.FileMode{
		".": 0o700, "private": 0o700, "public": 0o755,
		"manifest.json": 0o600, "inventory.dsse.json": 0o644,
		"private/enrollment.json": 0o600,
		"public/control-ca.pem":   0o644, "public/site-policy.dsse.json": 0o644,
		"public/site-root.public": 0o644,
	}); err != nil {
		return verifiedSiteNodePackage{}, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("open node package root: %w", err)
	}
	defer root.Close()
	manifestRaw, err := securefile.ReadRootMode(root, "manifest.json", maxArtifactBytes, 0o600)
	if err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("read node package manifest: %w", err)
	}
	var manifest siteNodePackageManifest
	if err := dsse.DecodeStrictInto(manifestRaw, maxArtifactBytes, &manifest); err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("decode node package manifest: %w", err)
	}
	if err := validateSiteNodeManifest(manifest); err != nil {
		return verifiedSiteNodePackage{}, err
	}
	rootRaw, err := securefile.ReadRootMode(root, "public/site-root.public", maxArtifactBytes, 0o644)
	if err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("read node package site root: %w", err)
	}
	rootKey, err := decodeSiteNodePublicKey(rootRaw)
	if err != nil {
		return verifiedSiteNodePackage{}, err
	}
	if pinnedRoot != "" {
		pinned, err := readPublicKey(pinnedRoot)
		if err != nil {
			return verifiedSiteNodePackage{}, fmt.Errorf("read pinned site root: %w", err)
		}
		if !pinned.Equal(rootKey) {
			return verifiedSiteNodePackage{}, errors.New("node package site root does not match the independent pin")
		}
	}
	inventoryRaw, err := securefile.ReadRootMode(root, "inventory.dsse.json", maxArtifactBytes, 0o644)
	if err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("read signed site inventory: %w", err)
	}
	if digestSiteNodeBytes(inventoryRaw) != manifest.SiteInventorySHA256 {
		return verifiedSiteNodePackage{}, errors.New("node package site inventory digest does not match its manifest")
	}
	payload, _, err := dsse.Verify(inventoryRaw, sitePackagePayloadType, map[string]ed25519.PublicKey{"site-root-1": rootKey})
	if err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("verify node package site inventory: %w", err)
	}
	var inventory sitePackageInventory
	if err := dsse.DecodeStrictInto(payload, maxArtifactBytes, &inventory); err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("decode node package site inventory: %w", err)
	}
	if err := validateSiteInventory(inventory); err != nil {
		return verifiedSiteNodePackage{}, err
	}
	if inventory.SiteID != manifest.SiteID || inventory.TenantID != manifest.TenantID {
		return verifiedSiteNodePackage{}, errors.New("node package and signed site inventory identities do not match")
	}
	for _, name := range siteNodePublicFiles {
		expected, ok := siteInventoryFile(inventory, name)
		if !ok || expected.Mode != "0644" {
			return verifiedSiteNodePackage{}, fmt.Errorf("signed site inventory does not contain node trust file %q", name)
		}
		raw, err := securefile.ReadRootMode(root, filepath.FromSlash(name), maxArtifactBytes, 0o644)
		if err != nil {
			return verifiedSiteNodePackage{}, fmt.Errorf("read node trust file %q: %w", name, err)
		}
		if digestSiteNodeBytes(raw) != expected.SHA256 {
			return verifiedSiteNodePackage{}, fmt.Errorf("node trust file %q differs from the signed site inventory", name)
		}
	}
	policyRaw, err := securefile.ReadRootMode(root, "public/site-policy.dsse.json", maxArtifactBytes, 0o644)
	if err != nil {
		return verifiedSiteNodePackage{}, err
	}
	policyPayload, _, err := dsse.Verify(policyRaw, admission.PolicyPayloadType, map[string]ed25519.PublicKey{"site-root-1": rootKey})
	if err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("verify node package policy: %w", err)
	}
	var policy admission.SitePolicy
	if err := dsse.DecodeStrictInto(policyPayload, maxArtifactBytes, &policy); err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("decode node package policy: %w", err)
	}
	if err := policy.Validate(); err != nil || policy.PolicyID != manifest.SiteID || len(policy.Tenants) != 1 || policy.Tenants[0].TenantID != manifest.TenantID {
		return verifiedSiteNodePackage{}, errors.New("node package policy does not match the package identity")
	}
	enrollmentRaw, err := securefile.ReadRootMode(root, "private/enrollment.json", 64<<10, 0o600)
	if err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("read node enrollment capability: %w", err)
	}
	if digestSiteNodeBytes(enrollmentRaw) != manifest.EnrollmentSHA256 {
		return verifiedSiteNodePackage{}, errors.New("node enrollment capability digest does not match its manifest")
	}
	enrollment, err := controlclient.DecodeEnrollmentCapability(enrollmentRaw)
	if err != nil {
		return verifiedSiteNodePackage{}, err
	}
	if err := validatePreparedEnrollment(enrollment, manifest.TenantID, manifest.NodeID); err != nil {
		return verifiedSiteNodePackage{}, err
	}
	if enrollment.ControllerInstanceID != manifest.ControllerInstanceID || enrollment.EnrollmentID != manifest.EnrollmentID || enrollment.ExpiresAt != manifest.EnrollmentExpiresAt {
		return verifiedSiteNodePackage{}, errors.New("node enrollment capability does not match its manifest")
	}
	caRaw, err := securefile.ReadRootMode(root, "public/control-ca.pem", maxArtifactBytes, 0o644)
	if err != nil {
		return verifiedSiteNodePackage{}, err
	}
	if _, err := controlclient.New(manifest.ControlURL, "", caRaw); err != nil {
		return verifiedSiteNodePackage{}, fmt.Errorf("validate node package Control origin: %w", err)
	}
	rootDigest := sha256.Sum256(rootKey)
	return verifiedSiteNodePackage{
		directory: directory, manifest: manifest, enrollment: enrollment, rootKey: rootKey,
		rootDigest: "sha256:" + hex.EncodeToString(rootDigest[:]), manifestDigest: digestSiteNodeBytes(manifestRaw),
	}, nil
}

func validatePreparedEnrollment(enrollment controlclient.Enrollment, tenantID, nodeID string) error {
	if enrollment.ControllerInstanceID == "" || enrollment.EnrollmentID == "" || enrollment.EnrollmentToken == "" ||
		enrollment.NodeID != nodeID || !slices.Equal(enrollment.TenantIDs, []string{tenantID}) {
		return errors.New("Control returned an enrollment outside the requested site, tenant, or node identity")
	}
	expires, err := time.Parse(time.RFC3339Nano, enrollment.ExpiresAt)
	if err != nil || !expires.After(timeNow()) || expires.After(timeNow().Add(24*time.Hour+time.Second)) {
		return errors.New("Control returned an invalid enrollment expiry")
	}
	return nil
}

func validateSiteNodeManifest(manifest siteNodePackageManifest) error {
	if manifest.SchemaVersion != siteNodePackageSchema ||
		!validOptionalControlIdentifier(manifest.SiteID, 128) || manifest.SiteID == "" ||
		!validOptionalControlIdentifier(manifest.TenantID, 128) || manifest.TenantID == "" ||
		!validOptionalControlIdentifier(manifest.NodeID, 128) || manifest.NodeID == "" ||
		!validOptionalControlIdentifier(manifest.EnrollmentRequestID, 128) || manifest.EnrollmentRequestID == "" ||
		!validOptionalControlIdentifier(manifest.ExchangeRequestID, 128) || manifest.ExchangeRequestID == "" ||
		manifest.ControllerInstanceID == "" || manifest.EnrollmentID == "" || manifest.EnrollmentExpiresAt == "" ||
		!validSiteSHA256(manifest.SiteInventorySHA256) || !validSiteSHA256(manifest.EnrollmentSHA256) ||
		!slices.Equal(manifest.PublicFiles, siteNodePublicFiles) {
		return errors.New("site node package manifest is invalid")
	}
	return nil
}

func siteNodePackageOutputs(verified verifiedSitePackage, manifestRaw, enrollmentRaw []byte) ([]siteOutput, error) {
	root, err := os.OpenRoot(verified.directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	outputs := []siteOutput{
		{path: "manifest.json", contents: manifestRaw, mode: 0o600},
		{path: "inventory.dsse.json", contents: verified.inventoryRaw, mode: 0o644},
		{path: "private/enrollment.json", contents: enrollmentRaw, mode: 0o600},
	}
	for _, name := range siteNodePublicFiles {
		raw, err := securefile.ReadRootMode(root, filepath.FromSlash(name), maxArtifactBytes, 0o644)
		if err != nil {
			return nil, fmt.Errorf("read verified site file %q: %w", name, err)
		}
		outputs = append(outputs, siteOutput{path: name, contents: raw, mode: 0o644})
	}
	return outputs, nil
}

func publishSiteNodePackage(directory string, outputs []siteOutput) error {
	parent := filepath.Dir(directory)
	temporary, err := os.MkdirTemp(parent, ".steward-node-package-")
	if err != nil {
		return fmt.Errorf("reserve node package output: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	for _, directoryName := range []string{"private", "public"} {
		mode := fs.FileMode(0o755)
		if directoryName == "private" {
			mode = 0o700
		}
		if err := os.Mkdir(filepath.Join(temporary, directoryName), mode); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Join(temporary, directoryName), mode); err != nil {
			return err
		}
	}
	for _, output := range outputs {
		path := filepath.Join(temporary, filepath.FromSlash(output.path))
		if err := writeNewFile(path, output.contents, output.mode); err != nil {
			return fmt.Errorf("write node package %s: %w", output.path, err)
		}
		if err := setAndSyncSiteMode(path, output.mode); err != nil {
			return fmt.Errorf("set node package mode %s: %w", output.path, err)
		}
	}
	for _, name := range []string{"private", "public", "."} {
		directoryPath := temporary
		if name != "." {
			directoryPath = filepath.Join(temporary, name)
		}
		opened, err := os.Open(directoryPath)
		if err != nil {
			return err
		}
		if err := errors.Join(opened.Sync(), opened.Close()); err != nil {
			return err
		}
	}
	if _, err := verifySiteNodePackage(temporary, ""); err != nil {
		return fmt.Errorf("verify staged node package: %w", err)
	}
	if err := os.Rename(temporary, directory); err != nil {
		return fmt.Errorf("publish node package: %w", err)
	}
	if err := syncOutputDirectory(directory); err != nil {
		return err
	}
	committed = true
	return nil
}

func validatedNewPackagePath(path string) (string, error) {
	directory, err := filepath.Abs(path)
	if err != nil || directory == string(filepath.Separator) {
		return "", errors.New("package output directory is invalid")
	}
	if _, err := os.Lstat(directory); err == nil {
		return "", fmt.Errorf("package output directory %q already exists", directory)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(directory)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("package output parent must be a real directory that is not group- or world-writable")
	}
	return directory, nil
}

func verifyFixedPackageLayout(directory string, expected map[string]fs.FileMode) error {
	return filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		mode, ok := expected[relative]
		if !ok {
			return fmt.Errorf("package contains unexpected path %q", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() != (relative == "." || relative == "private" || relative == "public") ||
			(!entry.IsDir() && !info.Mode().IsRegular()) || info.Mode().Perm() != mode {
			return fmt.Errorf("package path %q has an invalid type or mode", relative)
		}
		return nil
	})
}

func siteInventoryFile(inventory sitePackageInventory, name string) (sitePackageFile, bool) {
	for _, file := range inventory.Files {
		if file.Path == name {
			return file, true
		}
	}
	return sitePackageFile{}, false
}

func decodeSiteNodePublicKey(raw []byte) (ed25519.PublicKey, error) {
	decoded, err := decodePublicKey(raw)
	if err != nil {
		return nil, errors.New("node package site root is not base64 Ed25519")
	}
	return decoded, nil
}

func derivedSiteNodeRequestID(kind, siteID, nodeID string) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + siteID + "\x00" + nodeID))
	return "site-node-" + kind + "-" + hex.EncodeToString(digest[:16])
}

func digestSiteNodeBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func siteNodePositionalsLast(arguments []string, count int) []string {
	if len(arguments) < count {
		return arguments
	}
	for _, argument := range arguments[:count] {
		if strings.HasPrefix(argument, "-") {
			return arguments
		}
	}
	normalized := append([]string(nil), arguments[count:]...)
	return append(normalized, arguments[:count]...)
}

func writeSiteNodeSummary(stdout io.Writer, verified verifiedSiteNodePackage, phase string) error {
	next := []string{
		"Transfer this owner-only directory to the intended node through an authenticated channel.",
		"On that node run: stewardctl site node activate " + verified.directory,
	}
	if phase == "verified" {
		next = next[:1]
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(siteNodeSummary{
		Directory: verified.directory, Phase: phase, SiteID: verified.manifest.SiteID,
		TenantID: verified.manifest.TenantID, NodeID: verified.manifest.NodeID,
		ControllerInstanceID: verified.manifest.ControllerInstanceID,
		EnrollmentID:         verified.manifest.EnrollmentID, EnrollmentExpiresAt: verified.manifest.EnrollmentExpiresAt,
		RootPublicSHA256: verified.rootDigest, NextSteps: next,
	})
}
