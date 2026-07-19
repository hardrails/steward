package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/hardrails/steward/internal/secretmaterial"
)

func secretCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) >= 2 && arguments[0] == "materialization" && arguments[1] == "check" {
		return checkSecretMaterialization(arguments[2:], stdout)
	}
	if len(arguments) >= 2 && arguments[0] == "materialization" && arguments[1] == "prepare" {
		return prepareSecretMaterialization(arguments[2:], stdout)
	}
	return errors.New("secret command requires materialization check or materialization prepare")
}

func checkSecretMaterialization(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("secret materialization check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "non-secret materialization manifest")
	rootPath := flags.String("root", "/var/lib/steward-gateway/secrets", "caller-owned materialization root")
	statusRootPath := flags.String("status-root", "/var/lib/steward-gateway/secret-status", "caller-owned materialization status root")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		return errors.New("secret materialization check requires -manifest and no positional arguments")
	}
	statusRootSet := false
	flags.Visit(func(flag *flag.Flag) {
		if flag.Name == "status-root" {
			statusRootSet = true
		}
	})
	manifest, err := secretmaterial.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	if manifest.SchemaVersion == secretmaterial.ManifestSchemaV1 && statusRootSet {
		return errors.New("secret materialization schema v1 does not support -status-root; migrate the manifest to schema v2")
	}
	var report secretmaterial.Report
	if manifest.SchemaVersion == secretmaterial.ManifestSchemaV2 {
		report, err = secretmaterial.CheckWithStatus(*rootPath, *statusRootPath, manifest)
	} else {
		report, err = secretmaterial.Check(*rootPath, manifest)
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode secret materialization report: %w", err)
	}
	return nil
}

func prepareSecretMaterialization(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("secret materialization prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "epoch-aware non-secret materialization manifest")
	rootPath := flags.String("root", "/var/lib/steward-gateway/secrets", "caller-owned materialization root")
	statusRootPath := flags.String("status-root", "/var/lib/steward-gateway/secret-status", "caller-owned materialization status root")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		return errors.New("secret materialization prepare requires -manifest and no positional arguments")
	}
	manifest, err := secretmaterial.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	if err := secretmaterial.Prepare(*rootPath, *statusRootPath, manifest); err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		SchemaVersion string `json:"schema_version"`
		Prepared      bool   `json:"prepared"`
	}{SchemaVersion: secretmaterial.ManifestSchemaV2, Prepared: true}); err != nil {
		return fmt.Errorf("encode secret materialization preparation: %w", err)
	}
	return nil
}
