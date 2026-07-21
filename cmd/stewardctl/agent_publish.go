package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/ocibundle"
	"github.com/hardrails/steward/internal/securefile"
)

type agentPublicationContract struct {
	profile     admission.ProfileRef
	command     []string
	statePath   string
	serviceID   string
	servicePort int
}

type agentPublishSummary struct {
	AgentName      string `json:"agent_name"`
	Runtime        string `json:"runtime"`
	Capsule        string `json:"capsule"`
	CapsuleDigest  string `json:"capsule_digest"`
	ManifestDigest string `json:"manifest_digest"`
	ConfigDigest   string `json:"config_digest"`
	Platform       string `json:"platform"`
}

func agentPublish(arguments []string, stdout io.Writer) error {
	arguments = sitePositionalLast(arguments)
	flags := flag.NewFlagSet("agent publish", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "agent.bundle.json", "portable agent bundle")
	archivePath := flags.String("archive", "", "single-image OCI or Docker archive")
	outputPath := flags.String("out", "capsule.dsse.json", "new publisher-signed capsule")
	capsuleID := flags.String("capsule-id", "", "stable published capsule identity")
	pinnedRoot := flags.String("site-root-public-key", "", "independently pinned site-root public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 || *archivePath == "" || *outputPath == "" {
		return errors.New("agent publish requires one site package directory, -archive, and -out")
	}
	siteDirectory, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return errors.New("site package directory is invalid")
	}
	verifiedSite, err := verifySitePackage(siteDirectory, *pinnedRoot)
	if err != nil {
		return err
	}
	bundleRaw, err := readCLIArtifact(*bundlePath)
	if err != nil {
		return fmt.Errorf("read agent bundle: %w", err)
	}
	bundle, err := agentapp.DecodeBundle(bundleRaw)
	if err != nil {
		return err
	}
	contract, ok := agentPublicationContractFor(bundle.Definition.Runtime.Engine)
	if !ok {
		return errors.New("agent runtime has no publishable Steward contract")
	}
	image, err := ocibundle.Inspect(*archivePath, ocibundle.DefaultLimits())
	if err != nil {
		return fmt.Errorf("inspect agent image archive: %w", err)
	}
	repository, manifestDigest, ok := strings.Cut(bundle.Definition.Runtime.Image, "@")
	if !ok || repository == "" || manifestDigest != image.ManifestDigest {
		return errors.New("agent bundle image does not match the inspected archive manifest")
	}
	if *capsuleID == "" {
		*capsuleID = bundle.Definition.Name
	}
	capsule := admission.ProfileCapsule{
		SchemaVersion: admission.SchemaV1, CapsuleID: *capsuleID, PublisherKeyID: "publisher-1",
		Profile: contract.profile,
		Image: admission.ImageIdentity{
			Repository: repository, ManifestDigest: image.ManifestDigest, ConfigDigest: image.ConfigDigest,
			Platform: admission.Platform{OS: image.Platform.OS, Architecture: image.Platform.Architecture, Variant: image.Platform.Variant},
		},
		Command: contract.command,
		Resources: admission.ResourceLimits{
			MemoryBytes: bundle.Definition.Resources.MemoryMiB * 1024 * 1024,
			CPUMillis:   bundle.Definition.Resources.CPUMillis, PIDs: bundle.Definition.Resources.PIDs,
		},
		Capabilities: admission.Capabilities{
			State: bundle.Definition.State.Persistent, Inference: true, Service: true,
			Egress:    len(bundle.Definition.Capabilities.EgressRouteIDs) > 0,
			Connector: len(bundle.Definition.Capabilities.ConnectorIDs) > 0,
		},
		State:   admission.StateShape{SchemaVersion: "v1", Path: contract.statePath},
		Service: admission.ServiceShape{ID: contract.serviceID, Port: contract.servicePort},
	}
	if err := capsule.Validate(timeNow().UTC()); err != nil {
		return fmt.Errorf("validate published capsule: %w", err)
	}
	publisherKey, err := readPrivateKey(filepath.Join(siteDirectory, "private", "publisher.private.pem"))
	if err != nil {
		return fmt.Errorf("read site publisher key: %w", err)
	}
	if err := validateSitePublisherKey(verifiedSite.policy, publisherKey); err != nil {
		return err
	}
	payload, err := json.Marshal(capsule)
	if err != nil {
		return err
	}
	envelope, err := dsse.Sign(admission.CapsulePayloadType, payload, "publisher-1", publisherKey)
	if err != nil {
		return err
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		return err
	}
	policyRaw, err := securefile.Read(filepath.Join(siteDirectory, "public", "site-policy.dsse.json"), maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return err
	}
	if _, err := admission.VerifyCapsuleForImport(
		raw, policyRaw, map[string]ed25519.PublicKey{"site-root-1": verifiedSite.rootKey},
		timeNow().UTC(), admission.DefaultProfiles(),
	); err != nil {
		return fmt.Errorf("verify published capsule against site policy: %w", err)
	}
	if err := writeNewFile(*outputPath, raw, 0o600); err != nil {
		return fmt.Errorf("write published capsule: %w", err)
	}
	platform := image.Platform.OS + "/" + image.Platform.Architecture
	if image.Platform.Variant != "" {
		platform += "/" + image.Platform.Variant
	}
	return writeAgentJSON(stdout, agentPublishSummary{
		AgentName: bundle.Definition.Name, Runtime: bundle.Definition.Runtime.Engine,
		Capsule: *outputPath, CapsuleDigest: dsse.Digest(raw), ManifestDigest: image.ManifestDigest,
		ConfigDigest: image.ConfigDigest, Platform: platform,
	})
}

func agentPublicationContractFor(runtime string) (agentPublicationContract, bool) {
	var ref admission.ProfileRef
	switch runtime {
	case "hermes":
		ref = admission.ProfileRef{ID: "hermes-v1", Version: "v1"}
	case "openclaw":
		ref = admission.ProfileRef{ID: "openclaw-v1", Version: "v1"}
	default:
		return agentPublicationContract{}, false
	}
	profile, ok := admission.DefaultProfiles().Lookup(ref)
	if !ok || len(profile.Command) == 0 || profile.ServiceID == "" || profile.ServicePort == 0 {
		return agentPublicationContract{}, false
	}
	return agentPublicationContract{
		profile: profile.Ref, command: append([]string(nil), profile.Command...), statePath: profile.StatePath,
		serviceID: profile.ServiceID, servicePort: profile.ServicePort,
	}, true
}

func validateSitePublisherKey(policy admission.SitePolicy, privateKey ed25519.PrivateKey) error {
	for _, publisher := range policy.Publishers {
		if publisher.KeyID != "publisher-1" {
			continue
		}
		public, err := base64.StdEncoding.Strict().DecodeString(publisher.PublicKey)
		if err != nil || !bytes.Equal(public, privateKey.Public().(ed25519.PublicKey)) || publisher.Revoked {
			break
		}
		return nil
	}
	return errors.New("site publisher key does not match active signed policy authority")
}
