// Package clustersubstrate defines Steward's pinned cluster substrate and
// deterministic host configuration. It performs no host mutation.
package clustersubstrate

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	SchemaVersion = "steward.cluster-substrate-lock.v1"
	Provider      = "rke2"
)

//go:embed source-lock.json
var sourceLock []byte

type Artifact struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Architecture struct {
	Bundle    Artifact `json:"bundle"`
	Images    Artifact `json:"images"`
	Checksums Artifact `json:"checksums"`
}

type Lock struct {
	SchemaVersion string                  `json:"schema_version"`
	Provider      string                  `json:"provider"`
	Channel       string                  `json:"channel"`
	Version       string                  `json:"version"`
	ObservedAt    string                  `json:"observed_at"`
	Repository    string                  `json:"repository"`
	License       string                  `json:"license"`
	Architectures map[string]Architecture `json:"architectures"`
}

func CurrentLock() (Lock, error) {
	return ParseLock(sourceLock)
}

func ParseLock(raw []byte) (Lock, error) {
	var lock Lock
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return Lock{}, fmt.Errorf("decode cluster substrate lock: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Lock{}, errors.New("cluster substrate lock contains trailing JSON")
		}
		return Lock{}, fmt.Errorf("decode cluster substrate lock trailer: %w", err)
	}
	if err := lock.Validate(); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

var (
	versionPattern = regexp.MustCompile(`^v[1-9][0-9]*\.[0-9]+\.[0-9]+\+rke2r[1-9][0-9]*$`)
	shaPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

func (lock Lock) Validate() error {
	if lock.SchemaVersion != SchemaVersion {
		return fmt.Errorf("cluster substrate lock schema must be %q", SchemaVersion)
	}
	if lock.Provider != Provider || lock.Channel != "stable" {
		return errors.New("cluster substrate lock must select the RKE2 stable channel")
	}
	if !versionPattern.MatchString(lock.Version) {
		return errors.New("cluster substrate version is invalid")
	}
	if _, err := time.Parse(time.RFC3339, lock.ObservedAt); err != nil {
		return errors.New("cluster substrate observation time is invalid")
	}
	if lock.Repository != "https://github.com/rancher/rke2" || lock.License != "Apache-2.0" {
		return errors.New("cluster substrate source identity is invalid")
	}
	if len(lock.Architectures) != 2 {
		return errors.New("cluster substrate lock must contain exactly amd64 and arm64")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		value, ok := lock.Architectures[arch]
		if !ok {
			return fmt.Errorf("cluster substrate lock is missing %s", arch)
		}
		for kind, artifact := range map[string]Artifact{
			"bundle": value.Bundle, "images": value.Images, "checksums": value.Checksums,
		} {
			if err := validateArtifact(lock.Version, arch, kind, artifact); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateArtifact(version, arch, kind string, artifact Artifact) error {
	if !namePattern.MatchString(artifact.Name) || artifact.Size <= 0 || artifact.Size > 2<<30 || !shaPattern.MatchString(artifact.SHA256) {
		return fmt.Errorf("cluster substrate %s %s artifact metadata is invalid", arch, kind)
	}
	parsed, err := url.Parse(artifact.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("cluster substrate %s %s artifact URL is invalid", arch, kind)
	}
	expectedPrefix := "/rancher/rke2/releases/download/" + version + "/"
	if !strings.HasPrefix(parsed.Path, expectedPrefix) ||
		!strings.HasSuffix(parsed.Path, "/"+artifact.Name) {
		return fmt.Errorf("cluster substrate %s %s artifact URL is outside the pinned release", arch, kind)
	}
	return nil
}

func (lock Lock) Artifact(arch, kind string) (Artifact, error) {
	architecture, ok := lock.Architectures[arch]
	if !ok {
		return Artifact{}, errors.New("cluster architecture must be amd64 or arm64")
	}
	switch kind {
	case "bundle":
		return architecture.Bundle, nil
	case "images":
		return architecture.Images, nil
	case "checksums":
		return architecture.Checksums, nil
	default:
		return Artifact{}, errors.New("cluster artifact must be bundle, images, or checksums")
	}
}

func SupportedArchitectures() []string {
	return slices.Clone([]string{"amd64", "arm64"})
}
