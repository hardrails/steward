// Package imageimport authenticates, snapshots, sanitizes, and imports one
// signed OCI image without reopening an untrusted source pathname.
package imageimport

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/ocibundle"
)

const MaxTimeout = 24 * time.Hour

// Request contains only already-bounded local activation inputs. Archive is
// optional for the legacy image-import command and required when a signed agent
// release binds the exact source bytes.
type Request struct {
	ArchivePath     string
	Archive         ocibundle.ArchiveIdentity
	CapsuleEnvelope []byte
	PolicyEnvelope  []byte
	SiteRoots       map[string]ed25519.PublicKey
	Now             time.Time
	DockerSocket    string
	Timeout         time.Duration
}

// Result identifies both the source archive and the exact image authorized by
// the publisher capsule and site policy.
type Result struct {
	Imported       bool                      `json:"imported"`
	Repository     string                    `json:"repository"`
	CapsuleDigest  string                    `json:"capsule_digest"`
	PolicyDigest   string                    `json:"policy_digest"`
	PublisherKeyID string                    `json:"publisher_key_id"`
	SiteRootKeyID  string                    `json:"site_root_key_id"`
	Archive        ocibundle.ArchiveIdentity `json:"archive"`
	Image          ocibundle.Image           `json:"image"`
}

// Execute verifies all signed authority before Docker receives bytes. When
// Request.Archive is present, its digest and size are checked against the same
// sealed snapshot later verified, sanitized, and streamed to Docker.
func Execute(ctx context.Context, request Request) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("image import context is required")
	}
	if request.ArchivePath == "" || len(request.CapsuleEnvelope) == 0 || len(request.PolicyEnvelope) == 0 ||
		len(request.SiteRoots) == 0 || request.Now.IsZero() || request.DockerSocket == "" ||
		request.Timeout <= 0 || request.Timeout > MaxTimeout {
		return Result{}, errors.New("image import request is incomplete or unbounded")
	}
	for keyID, public := range request.SiteRoots {
		if keyID == "" || len(public) != ed25519.PublicKeySize {
			return Result{}, errors.New("image import site-root trust is invalid")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	verified, err := admission.VerifyCapsuleForImport(
		request.CapsuleEnvelope,
		request.PolicyEnvelope,
		request.SiteRoots,
		request.Now.UTC(),
		admission.DefaultProfiles(),
	)
	if err != nil {
		return Result{}, fmt.Errorf("authorize image import: %w", err)
	}
	expected := ocibundle.Identity{
		ManifestDigest: verified.Capsule.Image.ManifestDigest,
		ConfigDigest:   verified.Capsule.Image.ConfigDigest,
		Platform: ocibundle.Platform{
			OS:           verified.Capsule.Image.Platform.OS,
			Architecture: verified.Capsule.Image.Platform.Architecture,
			Variant:      verified.Capsule.Image.Platform.Variant,
		},
	}
	var prepared *ocibundle.Prepared
	if request.Archive.Digest == "" && request.Archive.Bytes == 0 {
		prepared, err = ocibundle.PrepareContext(
			ctx, request.ArchivePath, expected, ocibundle.DefaultLimits(),
		)
	} else {
		prepared, err = ocibundle.PrepareBoundContext(
			ctx, request.ArchivePath, expected, request.Archive,
			ocibundle.DefaultLimits(),
		)
	}
	if err != nil {
		return Result{}, fmt.Errorf("prepare OCI archive: %w", err)
	}
	defer prepared.Close()

	docker := executor.NewDockerHTTPWithTimeout(request.DockerSocket, request.Timeout)
	imported := false
	imageReference := verified.Capsule.Image.Repository + "@" + expected.ManifestDigest
	observed, inspectErr := docker.InspectSignedImage(ctx, imageReference, expected.ConfigDigest)
	if errors.Is(inspectErr, executor.ErrNotFound) {
		loadReader, err := prepared.Reader()
		if err != nil {
			return Result{}, fmt.Errorf("open prepared OCI archive: %w", err)
		}
		if err := docker.LoadImage(ctx, loadReader); err != nil {
			return Result{}, fmt.Errorf("load prepared OCI archive: %w", err)
		}
		imported = true
		observed, inspectErr = docker.InspectSignedImage(ctx, imageReference, expected.ConfigDigest)
	}
	if inspectErr != nil {
		return Result{}, fmt.Errorf("inspect imported image config: %w", inspectErr)
	}
	if err := executor.ValidateImage(observed, executor.ImageRequirement{
		ManifestDigest: expected.ManifestDigest,
		ConfigDigest:   expected.ConfigDigest,
		OS:             expected.Platform.OS,
		Architecture:   expected.Platform.Architecture,
		Variant:        expected.Platform.Variant,
	}); err != nil {
		return Result{}, fmt.Errorf("validate imported image config: %w", err)
	}
	if err := prepared.Close(); err != nil {
		return Result{}, fmt.Errorf("close prepared OCI archive: %w", err)
	}
	return Result{
		Imported:       imported,
		Repository:     verified.Capsule.Image.Repository,
		CapsuleDigest:  verified.CapsuleDigest,
		PolicyDigest:   verified.PolicyDigest,
		PublisherKeyID: verified.PublisherKeyID,
		SiteRootKeyID:  verified.SiteRootKeyID,
		Archive:        prepared.Archive,
		Image:          prepared.Image,
	}, nil
}
