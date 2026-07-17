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
	if len(arguments) < 2 || arguments[0] != "materialization" || arguments[1] != "check" {
		return errors.New("secret command requires materialization check")
	}
	flags := flag.NewFlagSet("secret materialization check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "non-secret materialization manifest")
	rootPath := flags.String("root", "/var/lib/steward-gateway/secrets", "caller-owned materialization root")
	if err := flags.Parse(arguments[2:]); err != nil {
		return err
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		return errors.New("secret materialization check requires -manifest and no positional arguments")
	}
	manifest, err := secretmaterial.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	report, err := secretmaterial.Check(*rootPath, manifest)
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
