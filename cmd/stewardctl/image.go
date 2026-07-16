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

	"github.com/hardrails/steward/internal/imageimport"
	"github.com/hardrails/steward/internal/ocibundle"
)

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
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := imageimport.Execute(ctx, imageimport.Request{
		ArchivePath:     *archive,
		CapsuleEnvelope: capsuleEnvelope,
		PolicyEnvelope:  policyEnvelope,
		SiteRoots:       map[string]ed25519.PublicKey{*siteRootKeyID: siteRoot},
		Now:             time.Now().UTC(),
		DockerSocket:    *dockerSocket,
		Timeout:         *timeout,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}
