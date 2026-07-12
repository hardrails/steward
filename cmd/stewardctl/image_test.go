package main

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
)

func TestImageImportLoadsPreparedBytesAfterSourcePathSwap(t *testing.T) {
	directory := t.TempDir()
	archive, manifestDigest, configDigest, extraPath := writeImageImportArchive(t, directory)

	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisherPublic, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := admission.ProfileCapsule{
		SchemaVersion: admission.SchemaV1, CapsuleID: "capsule-a", PublisherKeyID: "publisher-1",
		Profile: admission.ProfileRef{ID: "generic-v1", Version: "v1"},
		Image: admission.ImageIdentity{
			Repository: "registry.example/agent", ManifestDigest: manifestDigest, ConfigDigest: configDigest,
			Platform: admission.Platform{OS: "linux", Architecture: "amd64", Variant: "v1"},
		},
		Command: []string{"/agent"}, Resources: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		State: admission.StateShape{SchemaVersion: "v1", Path: "/state"},
	}
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1, PolicyID: "site-a", PolicyEpoch: 1,
		Publishers: []admission.PublisherRule{{
			KeyID: "publisher-1", PublicKey: base64.StdEncoding.EncodeToString(publisherPublic),
			AllowedProfiles:     []admission.ProfileRef{{ID: "generic-v1", Version: "v1"}},
			AllowedRepositories: []string{"registry.example/agent"}, AllowedManifestDigests: []string{manifestDigest},
			ResourceCeiling: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		}},
		Tenants: []admission.TenantRule{{
			TenantID: "tenant-a", PublisherKeyIDs: []string{"publisher-1"},
			ResourceCeiling: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		}},
	}
	capsulePath := filepath.Join(directory, "capsule.dsse.json")
	policyPath := filepath.Join(directory, "policy.dsse.json")
	writeSignedJSON(t, capsulePath, admission.CapsulePayloadType, capsule, "publisher-1", publisherPrivate)
	writeSignedJSON(t, policyPath, admission.PolicyPayloadType, policy, "site-root", rootPrivate)
	rootPath := filepath.Join(directory, "site-root.public")
	if err := os.WriteFile(rootPath, []byte(base64.StdEncoding.EncodeToString(rootPublic)), 0o600); err != nil {
		t.Fatal(err)
	}

	socketDirectory, err := os.MkdirTemp("", "steward-import-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDirectory)
	socket := filepath.Join(socketDirectory, "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	loaded := false
	var loadBytes []byte
	var handlerErr error
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case request.Method == http.MethodGet && !loaded:
			// This happens only after Prepare has completed. If stewardctl opens the
			// pathname again, Docker will receive these attacker bytes instead.
			if err := os.Rename(archive, archive+".verified"); err != nil {
				handlerErr = err
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(archive, []byte("attacker path replacement"), 0o600); err != nil {
				handlerErr = err
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			writer.WriteHeader(http.StatusNotFound)
		case request.Method == http.MethodPost && request.URL.Path == "/v1.41/images/load":
			loadBytes, handlerErr = io.ReadAll(io.LimitReader(request.Body, 16<<20))
			if handlerErr != nil {
				http.Error(writer, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			loaded = true
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte("{}\n"))
		case request.Method == http.MethodGet && loaded:
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(writer, `{"Id":%q,"Os":"linux","Architecture":"amd64","Variant":"v1","Config":{"Volumes":{}}}`, configDigest)
		default:
			http.Error(writer, "unexpected Docker request", http.StatusBadRequest)
		}
	})}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()

	var output bytes.Buffer
	err = importImageArchive([]string{
		"-archive", archive,
		"-capsule", capsulePath,
		"-policy", policyPath,
		"-site-root-public-key", rootPath,
		"-site-root-key-id", "site-root",
		"-docker-socket", socket,
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if handlerErr != nil {
		t.Fatal(handlerErr)
	}
	if !loaded {
		t.Fatal("Docker did not receive a load request")
	}
	entries := imageImportTarEntries(t, loadBytes)
	if _, ok := entries["repositories"]; ok {
		t.Fatal("command sent Docker a repositories file")
	}
	if _, ok := entries[extraPath]; ok {
		t.Fatal("command sent Docker an unreferenced blob")
	}
	if bytes.Contains(loadBytes, []byte("registry.example/agent:approved")) || bytes.Contains(loadBytes, []byte("attacker path replacement")) {
		t.Fatal("command sent Docker a repository tag or source-path replacement")
	}
	var compatibility []struct {
		RepoTags []string `json:"RepoTags"`
	}
	if err := json.Unmarshal(entries["manifest.json"], &compatibility); err != nil {
		t.Fatal(err)
	}
	if len(compatibility) != 1 || len(compatibility[0].RepoTags) != 0 {
		t.Fatalf("Docker load compatibility manifest = %#v", compatibility)
	}
}

func writeImageImportArchive(t *testing.T, directory string) (string, string, string, string) {
	t.Helper()
	layer := []byte("one image-import test layer")
	layerDigest := imageImportDigest(layer)
	config, err := json.Marshal(map[string]any{
		"architecture": "amd64", "os": "linux", "variant": "v1",
		"config": map[string]any{"Env": []string{"PATH=/bin"}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{layerDigest}},
	})
	if err != nil {
		t.Fatal(err)
	}
	configDigest := imageImportDigest(config)
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(config),
		},
		"layers": []any{map[string]any{
			"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layerDigest, "size": len(layer),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := imageImportDigest(manifest)
	index, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestDigest, "size": len(manifest),
			"platform": map[string]any{"os": "linux", "architecture": "amd64", "variant": "v1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := "blobs/sha256/" + strings.TrimPrefix(manifestDigest, "sha256:")
	configPath := "blobs/sha256/" + strings.TrimPrefix(configDigest, "sha256:")
	layerPath := "blobs/sha256/" + strings.TrimPrefix(layerDigest, "sha256:")
	compatibility, err := json.Marshal([]any{map[string]any{
		"Config": configPath, "RepoTags": []string{"registry.example/agent:approved"}, "Layers": []string{layerPath},
	}})
	if err != nil {
		t.Fatal(err)
	}
	extra := []byte("unreferenced command-test blob")
	extraPath := "blobs/sha256/" + strings.TrimPrefix(imageImportDigest(extra), "sha256:")
	entries := map[string][]byte{
		"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": index, "manifest.json": compatibility,
		"repositories": []byte(`{"attacker":{"latest":"polluting-tag"}}`),
		manifestPath:   manifest, configPath: config, layerPath: layer, extraPath: extra,
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	archive := filepath.Join(directory, "image.tar")
	file, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for _, name := range names {
		raw := entries[name]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o444, Size: int64(len(raw)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return archive, manifestDigest, configDigest, extraPath
}

func writeSignedJSON(t *testing.T, path, payloadType string, value any, keyID string, key ed25519.PrivateKey) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(payloadType, payload, keyID, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func imageImportTarEntries(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	entries := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(raw))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = content
	}
	return entries
}

func imageImportDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
