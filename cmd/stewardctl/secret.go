package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hardrails/steward/internal/openbaobundle"
	"github.com/hardrails/steward/internal/secretmaterial"
)

func secretCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) >= 2 && arguments[0] == "materialization" && arguments[1] == "check" {
		return checkSecretMaterialization(arguments[2:], stdout)
	}
	if len(arguments) >= 2 && arguments[0] == "materialization" && arguments[1] == "prepare" {
		return prepareSecretMaterialization(arguments[2:], stdout)
	}
	if len(arguments) >= 2 && arguments[0] == "openbao" && arguments[1] == "compile" {
		return compileOpenBaoMaterializer(arguments[2:], stdout)
	}
	return errors.New("secret command requires materialization check, materialization prepare, or openbao compile")
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
	manifest, err := secretmaterial.LoadManifest(*manifestPath)
	if err != nil {
		return err
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

func compileOpenBaoMaterializer(arguments []string, stdout io.Writer) (returnErr error) {
	flags := flag.NewFlagSet("secret openbao compile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "strict non-secret OpenBao materializer plan")
	outputPath := flags.String("out", "", "new output directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *planPath == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("secret openbao compile requires -plan, -out, and no positional arguments")
	}
	if !filepath.IsAbs(*outputPath) || filepath.Clean(*outputPath) != *outputPath {
		return errors.New("OpenBao bundle output must be a clean absolute path")
	}
	plan, err := openbaobundle.LoadPlan(*planPath)
	if err != nil {
		return err
	}
	files, err := openbaobundle.Compile(plan)
	if err != nil {
		return err
	}
	if err := os.Mkdir(*outputPath, 0o700); err != nil {
		return fmt.Errorf("create OpenBao bundle directory: %w", err)
	}
	created := make([]string, 0, len(files))
	defer func() {
		if returnErr == nil {
			return
		}
		for _, path := range created {
			_ = os.Remove(path)
		}
		_ = os.Remove(*outputPath)
	}()
	for _, file := range files {
		path := filepath.Join(*outputPath, file.Name)
		if err := writeNewFile(path, file.Data, os.FileMode(file.Mode)); err != nil {
			return fmt.Errorf("write OpenBao bundle file %q: %w", file.Name, err)
		}
		created = append(created, path)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		SchemaVersion string   `json:"schema_version"`
		OutputPath    string   `json:"output_path"`
		Files         []string `json:"files"`
	}{SchemaVersion: openbaobundle.PlanSchemaV1, OutputPath: *outputPath,
		Files: []string{"agent.hcl", "materialization.json", "openbao-read-policy.hcl", "steward-openbao-agent.service"}}); err != nil {
		return fmt.Errorf("encode OpenBao bundle summary: %w", err)
	}
	return nil
}
