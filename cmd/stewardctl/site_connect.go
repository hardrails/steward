package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/securefile"
)

type siteConnectionSummary struct {
	SiteID         string `json:"site_id"`
	TenantID       string `json:"tenant_id"`
	Context        string `json:"context"`
	CredentialID   string `json:"credential_id"`
	TokenFile      string `json:"token_file"`
	ControlURL     string `json:"control_url"`
	CAFile         string `json:"ca_file"`
	NodeID         string `json:"node_id,omitempty"`
	CurrentContext bool   `json:"current_context"`
}

func siteConnect(arguments []string, stdout io.Writer) error {
	contextual, err := applyCLIContext(append([]string{"operator", "issue"}, arguments...))
	if err != nil {
		return err
	}
	arguments = siteNodePositionalsLast(contextual[2:], 1)
	flags := flag.NewFlagSet("site connect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	contextName := flags.String("context", "", "saved CLI context name")
	output := flags.String("operator-token-out", "", "new owner-only tenant operator token")
	requestID := flags.String("request-id", "", "stable operator issuance identity")
	nodeID := flags.String("node-id", "", "optional default node identity")
	pinnedRoot := flags.String("site-root-public-key", "", "independently pinned site-root public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("site connect requires one site package directory")
	}
	siteDirectory, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return errors.New("site package directory is invalid")
	}
	verified, err := verifySitePackage(siteDirectory, *pinnedRoot)
	if err != nil {
		return err
	}
	if *contextName == "" {
		*contextName = verified.inventory.SiteID + "-" + verified.inventory.TenantID
	}
	if !validCLIContextName(*contextName) {
		return errors.New("site connection context name is invalid")
	}
	if !validOptionalControlIdentifier(*nodeID, 128) {
		return errors.New("site connection node identity is invalid")
	}
	if *requestID == "" {
		*requestID = derivedSiteNodeRequestID("operator", verified.inventory.SiteID, verified.inventory.TenantID)
	}
	if !validOptionalControlIdentifier(*requestID, 128) || *requestID == "" {
		return errors.New("site connection request identity is invalid")
	}
	if common.tokenFile == nil || *common.tokenFile == "" {
		return errors.New("site connect requires a site-administrator Control token or context")
	}
	if *common.caFile == "" {
		*common.caFile = filepath.Join(siteDirectory, "public", "control-ca.pem")
	}
	caPath, err := absoluteContextPath(*common.caFile, false)
	if err != nil {
		return fmt.Errorf("resolve site connection CA file: %w", err)
	}
	*common.caFile = caPath
	if *output == "" {
		*output = filepath.Join(filepath.Dir(siteDirectory), verified.inventory.SiteID+"-"+verified.inventory.TenantID+"-operator.token")
	}
	tokenPath, err := filepath.Abs(*output)
	if err != nil || tokenPath == string(filepath.Separator) {
		return errors.New("tenant operator token output is invalid")
	}
	if pathWithin(tokenPath, siteDirectory) {
		return errors.New("tenant operator token must not modify the signed site package")
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
	operator, err := client.IssueOperator(ctx, *requestID, "tenant_operator", verified.inventory.TenantID)
	if err != nil {
		return fmt.Errorf("issue tenant operator: %w", err)
	}
	if err := validateSiteTenantOperator(operator, verified.inventory.TenantID); err != nil {
		return err
	}
	if err := writeOrVerifySiteOperatorToken(tokenPath, operator.Token); err != nil {
		return err
	}
	if _, err := controlclient.NewFromFiles(*common.url, tokenPath, *common.caFile); err != nil {
		return fmt.Errorf("validate tenant operator connection: %w", err)
	}
	if err := saveSiteOperatorContext(
		*contextName, *common.url, tokenPath, *common.caFile,
		verified.inventory.TenantID, *nodeID,
	); err != nil {
		return fmt.Errorf("save tenant operator context: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(siteConnectionSummary{
		SiteID: verified.inventory.SiteID, TenantID: verified.inventory.TenantID,
		Context: *contextName, CredentialID: operator.CredentialID, TokenFile: tokenPath,
		ControlURL: *common.url, CAFile: *common.caFile, NodeID: *nodeID, CurrentContext: true,
	})
}

func saveSiteOperatorContext(name, controlURL, tokenFile, caFile, tenantID, nodeID string) error {
	return withCLIContextConfigMutation(func(config *cliContextConfig, path string) error {
		next, found := findCLIContext(*config, name)
		if !found {
			next = cliContext{Name: name}
		}
		for _, owned := range []struct {
			label    string
			existing string
			wanted   string
		}{
			{label: "Control URL", existing: next.ControlURL, wanted: controlURL},
			{label: "Control token", existing: next.TokenFile, wanted: tokenFile},
			{label: "Control CA", existing: next.CAFile, wanted: caFile},
			{label: "tenant", existing: next.TenantID, wanted: tenantID},
		} {
			if owned.existing != "" && owned.existing != owned.wanted {
				return fmt.Errorf("context %q already has a different %s", name, owned.label)
			}
		}
		if nodeID != "" && next.NodeID != "" && next.NodeID != nodeID {
			return fmt.Errorf("context %q already has a different node", name)
		}
		next.ControlURL = controlURL
		next.TokenFile = tokenFile
		next.CAFile = caFile
		next.TenantID = tenantID
		if nodeID != "" {
			next.NodeID = nodeID
		}
		upsertCLIContext(config, next)
		config.Current = name
		return writeCLIContextConfig(path, *config)
	})
}

func validateSiteTenantOperator(operator controlclient.Operator, tenantID string) error {
	if operator.CredentialID == "" || operator.Role != "tenant_operator" || operator.TenantID != tenantID ||
		operator.Token == "" || len(operator.Token) > 4096 || operator.Token != strings.TrimSpace(operator.Token) ||
		strings.ContainsAny(operator.Token, " \t\r\n\x00") || operator.CreatedAt == "" {
		return errors.New("Control returned an invalid tenant operator credential")
	}
	return nil
}

func writeOrVerifySiteOperatorToken(path, token string) error {
	contents := []byte(token + "\n")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(path)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("tenant operator token parent must be a real directory that is not group- or world-writable")
		}
		if err := writeNewFile(path, contents, 0o600); err != nil {
			return fmt.Errorf("write tenant operator token: %w", err)
		}
		return nil
	} else if err != nil {
		return err
	}
	retained, err := securefile.Read(path, 4096, securefile.OwnerOnly)
	if err != nil {
		return fmt.Errorf("read retained tenant operator token: %w", err)
	}
	if string(retained) != string(contents) {
		return errors.New("tenant operator token output already contains different authority")
	}
	return nil
}

func pathWithin(path, parent string) bool {
	relative, err := filepath.Rel(parent, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
