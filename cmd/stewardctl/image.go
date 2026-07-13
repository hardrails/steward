package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/ocibundle"
)

type imageImportOutput struct {
	Imported       bool            `json:"imported"`
	Repository     string          `json:"repository"`
	CapsuleDigest  string          `json:"capsule_digest"`
	PolicyDigest   string          `json:"policy_digest"`
	PublisherKeyID string          `json:"publisher_key_id"`
	SiteRootKeyID  string          `json:"site_root_key_id"`
	Image          ocibundle.Image `json:"image"`
}

func imageCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("image command requires inspect or import")
	}
	switch arguments[0] {
	case "inspect":
		return inspectImageArchive(arguments[1:], stdout)
	case "import":
		return importImageArchive(arguments[1:], stdout)
	default:
		return fmt.Errorf("unsupported image command %q", arguments[0])
	}
}

func inspectImageArchive(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("image inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	archive := flags.String("archive", "", "single-image Docker/OCI archive")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *archive == "" || flags.NArg() != 0 {
		return errors.New("image inspect requires -archive and no positional arguments")
	}
	image, err := ocibundle.Inspect(*archive, ocibundle.DefaultLimits())
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(image)
}

func importImageArchive(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("image import", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	archive := flags.String("archive", "", "single-image Docker/OCI archive")
	capsulePath := flags.String("capsule", "", "publisher-signed capsule DSSE envelope")
	policyPath := flags.String("policy", "", "site-root-signed policy DSSE envelope")
	siteRootPath := flags.String("site-root-public-key", "", "base64 Ed25519 site-root public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "site-root DSSE key ID")
	dockerSocket := flags.String("docker-socket", "/var/run/docker.sock", "Docker Engine Unix socket")
	timeout := flags.Duration("timeout", 30*time.Minute, "bounded Docker import timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *archive == "" || *capsulePath == "" || *policyPath == "" || *siteRootPath == "" ||
		*siteRootKeyID == "" || *dockerSocket == "" || *timeout <= 0 || *timeout > 24*time.Hour || flags.NArg() != 0 {
		return errors.New("image import requires -archive, -capsule, -policy, -site-root-public-key, -site-root-key-id, and bounded options")
	}
	capsuleEnvelope, err := readBounded(*capsulePath)
	if err != nil {
		return fmt.Errorf("read capsule: %w", err)
	}
	policyEnvelope, err := readBounded(*policyPath)
	if err != nil {
		return fmt.Errorf("read site policy: %w", err)
	}
	siteRoot, err := readPublicKey(*siteRootPath)
	if err != nil {
		return fmt.Errorf("read site root: %w", err)
	}
	verified, err := admission.VerifyCapsuleForImport(
		capsuleEnvelope, policyEnvelope,
		map[string]ed25519.PublicKey{*siteRootKeyID: siteRoot},
		time.Now().UTC(), admission.DefaultProfiles(),
	)
	if err != nil {
		return fmt.Errorf("authorize image import: %w", err)
	}
	expected := ocibundle.Identity{
		ManifestDigest: verified.Capsule.Image.ManifestDigest,
		ConfigDigest:   verified.Capsule.Image.ConfigDigest,
		Platform: ocibundle.Platform{
			OS: verified.Capsule.Image.Platform.OS, Architecture: verified.Capsule.Image.Platform.Architecture,
			Variant: verified.Capsule.Image.Platform.Variant,
		},
	}
	prepared, err := ocibundle.Prepare(*archive, expected, ocibundle.DefaultLimits())
	if err != nil {
		return fmt.Errorf("prepare OCI archive: %w", err)
	}
	defer prepared.Close()
	image := prepared.Image

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	docker := executor.NewDockerHTTPWithTimeout(*dockerSocket, *timeout)
	imported := false
	imageReference := verified.Capsule.Image.Repository + "@" + expected.ManifestDigest
	observed, inspectErr := docker.InspectSignedImage(ctx, imageReference, expected.ConfigDigest)
	if errors.Is(inspectErr, executor.ErrNotFound) {
		loadReader, err := prepared.Reader()
		if err != nil {
			return fmt.Errorf("open prepared OCI archive: %w", err)
		}
		if err := docker.LoadImage(ctx, loadReader); err != nil {
			return fmt.Errorf("load prepared OCI archive: %w", err)
		}
		imported = true
		observed, inspectErr = docker.InspectSignedImage(ctx, imageReference, expected.ConfigDigest)
	}
	if inspectErr != nil {
		return fmt.Errorf("inspect imported image config: %w", inspectErr)
	}
	if err := executor.ValidateImage(observed, executor.ImageRequirement{
		ManifestDigest: expected.ManifestDigest, ConfigDigest: expected.ConfigDigest, OS: expected.Platform.OS,
		Architecture: expected.Platform.Architecture, Variant: expected.Platform.Variant,
	}); err != nil {
		return fmt.Errorf("validate imported image config: %w", err)
	}
	if err := prepared.Close(); err != nil {
		return fmt.Errorf("close prepared OCI archive: %w", err)
	}
	return json.NewEncoder(stdout).Encode(imageImportOutput{
		Imported: imported, Repository: verified.Capsule.Image.Repository,
		CapsuleDigest: verified.CapsuleDigest, PolicyDigest: verified.PolicyDigest,
		PublisherKeyID: verified.PublisherKeyID, SiteRootKeyID: verified.SiteRootKeyID,
		Image: image,
	})
}
