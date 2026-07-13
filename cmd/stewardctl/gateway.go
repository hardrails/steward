package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/hardrails/steward/internal/gateway"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func gatewayCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("gateway command requires validate, route, or connector")
	}
	switch arguments[0] {
	case "validate":
		flags := flag.NewFlagSet("gateway validate", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		path := flags.String("config", "/etc/steward/gateway.json", "gateway configuration")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("gateway validate accepts no positional arguments")
		}
		config, routes, egressRoutes, token, err := gateway.LoadConfig(*path)
		if err != nil {
			return err
		}
		if _, err := gateway.Validate(config, routes, egressRoutes, token); err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, "gateway configuration valid")
		return err
	case "route":
		return gatewayRouteCommand(arguments[1:], stdout)
	case "connector":
		return gatewayConnectorCommand(arguments[1:], stdout)
	default:
		return fmt.Errorf("unsupported gateway command %q", arguments[0])
	}
}

func gatewayConnectorCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("gateway connector requires list or set")
	}
	action := arguments[0]
	flags := flag.NewFlagSet("gateway connector "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "/etc/steward/gateway.json", "gateway configuration")
	id := flags.String("id", "", "stable connector ID")
	baseURL := flags.String("base-url", "", "exact upstream HTTPS origin")
	credentialFile := flags.String("credential-file", "", "owner-only upstream credential file")
	credentialMode := flags.String("credential-mode", string(gateway.CredentialModeBearer), "bearer or x-api-key")
	allowInsecureHTTP := flags.Bool("allow-insecure-http", false, "explicitly permit a plaintext HTTP origin")
	maxConcurrent := flags.Int("max-concurrent", 4, "maximum concurrent calls for this connector")
	maxRequest := flags.Int64("max-request-bytes", 1<<20, "request body byte ceiling")
	maxResponse := flags.Int64("max-response-bytes", 4<<20, "response body byte ceiling")
	maxSeconds := flags.Int("max-seconds", 60, "call lifetime ceiling")
	maxCalls := flags.Int("max-calls-per-grant", 16, "durable call budget for one grant")
	receiptFile := flags.String("receipt-file", "", "signed connector receipt ledger path for an older config")
	receiptKeyFile := flags.String("receipt-key-file", "", "connector receipt private key path for an older config")
	receiptNodeID := flags.String("receipt-node-id", "", "stable connector receipt node identity for an older config")
	receiptEpoch := flags.Uint64("receipt-epoch", 1, "connector receipt key epoch for an older config")
	var cidrs, operations repeatedFlag
	flags.Var(&cidrs, "allow-cidr", "explicit resolved-address CIDR; repeat for more")
	flags.Var(&operations, "operation", "exact ID=METHOD:/path operation; repeat for more")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("gateway connector accepts no positional arguments")
	}
	config, _, _, _, err := gateway.LoadConfig(*path)
	if err != nil {
		return err
	}
	if action == "list" {
		if !onlyConfigFlagVisited(flags) {
			return errors.New("gateway connector list accepts only -config")
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(config.Connectors)
	}
	if action != "set" {
		return fmt.Errorf("unsupported gateway connector action %q", action)
	}
	if *id == "" || *baseURL == "" || *credentialFile == "" || len(operations) == 0 {
		return errors.New("gateway connector set requires -id, -base-url, -credential-file, and at least one -operation")
	}
	parsedOperations := make([]gateway.ConnectorOperation, 0, len(operations))
	for _, value := range operations {
		operation, err := parseConnectorOperation(value)
		if err != nil {
			return err
		}
		parsedOperations = append(parsedOperations, operation)
	}
	connector := gateway.Connector{
		ID: *id, BaseURL: *baseURL, CredentialFile: *credentialFile,
		CredentialMode: gateway.CredentialMode(*credentialMode), AllowInsecureHTTP: *allowInsecureHTTP,
		AllowedCIDRs: append([]string(nil), cidrs...), MaxConcurrent: *maxConcurrent,
		MaxRequestBytes: *maxRequest, MaxResponseBytes: *maxResponse, MaxSeconds: *maxSeconds,
		MaxCallsPerGrant: *maxCalls, Operations: parsedOperations,
	}
	if config.ConnectorReceiptFile == "" {
		if *receiptFile == "" || *receiptKeyFile == "" || *receiptNodeID == "" || *receiptEpoch == 0 {
			return errors.New("older gateway config requires -receipt-file, -receipt-key-file, -receipt-node-id, and a positive -receipt-epoch when adding its first connector")
		}
		config.ConnectorReceiptFile, config.ConnectorReceiptKeyFile = *receiptFile, *receiptKeyFile
		config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch = *receiptNodeID, *receiptEpoch
	} else if connectorReceiptFlagVisited(flags) {
		return errors.New("receipt flags are accepted only when upgrading a config without a connector receipt identity")
	}
	replaced := false
	for index := range config.Connectors {
		if config.Connectors[index].ID == *id {
			config.Connectors[index], replaced = connector, true
			break
		}
	}
	if !replaced {
		config.Connectors = append(config.Connectors, connector)
	}
	if err := writeGatewayConfig(*path, config); err != nil {
		return err
	}
	result := map[string]any{"connector": connector, "replaced": replaced, "activation": "systemctl reload steward-gateway.service"}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func parseConnectorOperation(value string) (gateway.ConnectorOperation, error) {
	identifier, rule, ok := strings.Cut(value, "=")
	method, path, methodOK := strings.Cut(rule, ":")
	if !ok || !methodOK || identifier == "" || method == "" || path == "" {
		return gateway.ConnectorOperation{}, fmt.Errorf("invalid operation %q; use ID=METHOD:/exact/path", value)
	}
	return gateway.ConnectorOperation{ID: identifier, Method: method, Path: path}, nil
}

func gatewayRouteCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("gateway route requires list or set")
	}
	action := arguments[0]
	flags := flag.NewFlagSet("gateway route "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "/etc/steward/gateway.json", "gateway configuration")
	id := flags.String("id", "", "stable route ID")
	maxConcurrent := flags.Int("max-concurrent", 8, "maximum concurrent requests")
	maxRequest := flags.Int64("max-request-bytes", 16<<20, "request or tunnel upload byte ceiling")
	maxResponse := flags.Int64("max-response-bytes", 256<<20, "response or tunnel download byte ceiling")
	maxSeconds := flags.Int("max-seconds", 900, "request/tunnel lifetime ceiling")
	var destinations, cidrs repeatedFlag
	flags.Var(&destinations, "destination", "allowed HOST:PORT; repeat for more")
	flags.Var(&cidrs, "allow-cidr", "explicit resolved-address CIDR pin; repeat for more")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("gateway route accepts no positional arguments")
	}
	config, _, _, _, err := gateway.LoadConfig(*path)
	if err != nil {
		return err
	}
	if action == "list" {
		if !onlyConfigFlagVisited(flags) {
			return errors.New("gateway route list accepts only -config")
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(config.EgressRoutes)
	}
	if action != "set" {
		return fmt.Errorf("unsupported gateway route action %q", action)
	}
	if *id == "" || len(destinations) == 0 {
		return errors.New("gateway route set requires -id and at least one -destination")
	}
	destinationRules := make([]gateway.EgressDestination, 0, len(destinations))
	for _, value := range destinations {
		host, portText, splitErr := net.SplitHostPort(value)
		port, portErr := strconv.Atoi(portText)
		if splitErr != nil || portErr != nil || host == "" || port < 1 || port > 65535 {
			return fmt.Errorf("invalid destination %q; use HOST:PORT (IPv6 in brackets)", value)
		}
		destinationRules = append(destinationRules, gateway.EgressDestination{Host: host, Ports: []int{port}, AllowedCIDRs: append([]string(nil), cidrs...)})
	}
	route := gateway.EgressRoute{ID: *id, Destinations: destinationRules, MaxConcurrent: *maxConcurrent,
		MaxRequestBytes: *maxRequest, MaxResponseBytes: *maxResponse, MaxTunnelSeconds: *maxSeconds}
	replaced := false
	for index := range config.EgressRoutes {
		if config.EgressRoutes[index].ID == *id {
			config.EgressRoutes[index], replaced = route, true
			break
		}
	}
	if !replaced {
		config.EgressRoutes = append(config.EgressRoutes, route)
	}
	if config.EgressAuditFile == "" {
		config.EgressAuditFile = "/var/lib/steward-gateway/egress-audit.jsonl"
	}
	if err := writeGatewayConfig(*path, config); err != nil {
		return err
	}
	result := map[string]any{"route": route, "replaced": replaced, "activation": "systemctl reload steward-gateway.service"}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func onlyConfigFlagVisited(flags *flag.FlagSet) bool {
	valid := true
	flags.Visit(func(visited *flag.Flag) {
		if visited.Name != "config" {
			valid = false
		}
	})
	return valid
}

func connectorReceiptFlagVisited(flags *flag.FlagSet) bool {
	found := false
	flags.Visit(func(visited *flag.Flag) {
		switch visited.Name {
		case "receipt-file", "receipt-key-file", "receipt-node-id", "receipt-epoch":
			found = true
		}
	})
	return found
}

func writeGatewayConfig(path string, config gateway.Config) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > maxArtifactBytes {
		return errors.New("gateway config must be a bounded regular file with no group/world write permission")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("gateway config ownership is unavailable")
	}
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".gateway.json.*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	loaded, routes, egressRoutes, token, err := gateway.LoadConfig(name)
	if err != nil {
		return fmt.Errorf("rendered gateway config is invalid: %w", err)
	}
	if _, err := gateway.Validate(loaded, routes, egressRoutes, token); err != nil {
		return fmt.Errorf("rendered gateway config is incompatible with retained state: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
