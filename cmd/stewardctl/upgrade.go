package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/executoruplink"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/journal"
	"github.com/hardrails/steward/internal/nodeclient"
	stewardruntime "github.com/hardrails/steward/internal/runtime"
)

const maxReleaseManifestBytes = 1 << 20

var upgradeStateNames = []string{
	"admission_fence",
	"connector_receipt_log",
	"evidence_log",
	"gateway_state",
	"operation_journal",
	"supervisor_state",
	"uplink_state",
}

type upgradeOptions struct {
	signedAdmission     string
	fenceFile           string
	journalFile         string
	evidenceFile        string
	uplinkStateFile     string
	supervisorStateFile string
	gatewayConfig       string
	releaseManifest     string
}

type observedStateFormats struct {
	AdmissionFence      *int `json:"admission_fence"`
	ConnectorReceiptLog *int `json:"connector_receipt_log"`
	EvidenceLog         *int `json:"evidence_log"`
	GatewayState        *int `json:"gateway_state"`
	OperationJournal    *int `json:"operation_journal"`
	SupervisorState     *int `json:"supervisor_state"`
	UplinkState         *int `json:"uplink_state"`
}

type upgradeInspection struct {
	SignedAdmission       string               `json:"signed_admission"`
	ActiveFences          int                  `json:"active_fences"`
	PendingOperations     int                  `json:"pending_operations"`
	RetainedGatewayGrants int                  `json:"retained_gateway_grants"`
	Formats               observedStateFormats `json:"formats"`
}

type upgradeDrainReport struct {
	upgradeInspection
	TargetCompatible *bool `json:"target_compatible"`
	Drained          bool  `json:"drained"`
}

type upgradeFormatReport struct {
	SignedAdmission  string               `json:"signed_admission"`
	Formats          observedStateFormats `json:"formats"`
	TargetCompatible *bool                `json:"target_compatible"`
}

type releaseFormatRange struct {
	ReadMin int `json:"read_min"`
	ReadMax int `json:"read_max"`
	Write   int `json:"write"`
}

type releaseManifest struct {
	Schema       string              `json:"schema"`
	Version      string              `json:"version"`
	OS           string              `json:"os"`
	Architecture string              `json:"arch"`
	StateFormats releaseStateFormats `json:"state_formats"`
	Files        json.RawMessage     `json:"files"`
}

type releaseStateFormats struct {
	AdmissionFence      releaseFormatRange `json:"admission_fence"`
	ConnectorReceiptLog releaseFormatRange `json:"connector_receipt_log"`
	EvidenceLog         releaseFormatRange `json:"evidence_log"`
	GatewayState        releaseFormatRange `json:"gateway_state"`
	OperationJournal    releaseFormatRange `json:"operation_journal"`
	SupervisorState     releaseFormatRange `json:"supervisor_state"`
	UplinkState         releaseFormatRange `json:"uplink_state"`
}

func upgradeCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || (arguments[0] != "check-drained" && arguments[0] != "inspect-formats") {
		return errors.New("upgrade command requires check-drained or inspect-formats")
	}
	action := arguments[0]
	options, err := parseUpgradeOptions(action, arguments[1:])
	if err != nil {
		return err
	}
	inspection, err := inspectUpgradeState(options)
	if err != nil {
		return err
	}
	compatible, compatibilityErr := checkTargetCompatibility(options.releaseManifest, inspection.Formats)
	if action == "inspect-formats" {
		report := upgradeFormatReport{SignedAdmission: options.signedAdmission, Formats: inspection.Formats, TargetCompatible: compatible}
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			return err
		}
		return compatibilityErr
	}
	drained := inspection.ActiveFences == 0 && inspection.PendingOperations == 0 && inspection.RetainedGatewayGrants == 0
	report := upgradeDrainReport{upgradeInspection: inspection, TargetCompatible: compatible, Drained: drained}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		return err
	}
	if compatibilityErr != nil {
		return compatibilityErr
	}
	if !drained {
		return drainAction(inspection)
	}
	return nil
}

func parseUpgradeOptions(action string, arguments []string) (upgradeOptions, error) {
	flags := flag.NewFlagSet("upgrade "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	signedAdmission := flags.String("signed-admission", "", "configured or unconfigured")
	fenceFile := flags.String("fence-file", "/var/lib/steward-executor/admission-fences.bin", "admission fence snapshot")
	journalFile := flags.String("journal-file", "/var/lib/steward-executor/operation-journal.bin", "operation journal")
	evidenceFile := flags.String("evidence-file", "/var/lib/steward-executor/evidence.bin", "evidence log")
	uplinkStateFile := flags.String("uplink-state-file", "/var/lib/steward-executor/uplink-state.json", "Executor uplink state")
	supervisorStateFile := flags.String("supervisor-state-file", "/var/lib/steward/state.json", "supervisor state")
	gatewayConfig := flags.String("gateway-config", "/etc/steward/gateway.json", "Gateway configuration")
	releaseManifest := flags.String("release-manifest", "", "target release.json compatibility manifest")
	if err := flags.Parse(arguments); err != nil {
		return upgradeOptions{}, err
	}
	if flags.NArg() != 0 {
		return upgradeOptions{}, fmt.Errorf("upgrade %s accepts no positional arguments", action)
	}
	if *signedAdmission != "configured" && *signedAdmission != "unconfigured" {
		return upgradeOptions{}, errors.New("-signed-admission must explicitly be configured or unconfigured")
	}
	for name, value := range map[string]string{
		"fence-file": *fenceFile, "journal-file": *journalFile, "evidence-file": *evidenceFile,
		"uplink-state-file": *uplinkStateFile, "supervisor-state-file": *supervisorStateFile,
		"gateway-config": *gatewayConfig,
	} {
		if strings.TrimSpace(value) == "" {
			return upgradeOptions{}, fmt.Errorf("-%s must not be empty", name)
		}
	}
	return upgradeOptions{
		signedAdmission: *signedAdmission, fenceFile: *fenceFile, journalFile: *journalFile,
		evidenceFile: *evidenceFile, uplinkStateFile: *uplinkStateFile,
		supervisorStateFile: *supervisorStateFile, gatewayConfig: *gatewayConfig,
		releaseManifest: *releaseManifest,
	}, nil
}

func inspectUpgradeState(options upgradeOptions) (upgradeInspection, error) {
	result := upgradeInspection{SignedAdmission: options.signedAdmission}
	required := options.signedAdmission == "configured"

	present, err := requiredOrPresent(options.fenceFile, required, "admission fence store")
	if err != nil {
		return upgradeInspection{}, err
	}
	if present {
		store, err := admission.OpenFenceStore(options.fenceFile)
		if err != nil {
			return upgradeInspection{}, fmt.Errorf("inspect admission fence store: %w", err)
		}
		result.Formats.AdmissionFence = integerPointer(store.FormatVersion())
		for _, record := range store.Records() {
			if record.Present {
				result.ActiveFences++
			}
		}
	}

	present, err = requiredOrPresent(options.journalFile, required, "operation journal")
	if err != nil {
		return upgradeInspection{}, err
	}
	if present {
		operations, err := journal.OpenForValidation(options.journalFile)
		if err != nil {
			return upgradeInspection{}, fmt.Errorf("inspect operation journal: %w", err)
		}
		result.PendingOperations = len(operations.Pending())
		if version, observed := operations.FormatVersion(); observed {
			result.Formats.OperationJournal = integerPointer(version)
		}
		if err := operations.Close(); err != nil {
			return upgradeInspection{}, fmt.Errorf("close operation journal after inspection: %w", err)
		}
	}

	present, err = requiredOrPresent(options.evidenceFile, required, "evidence log")
	if err != nil {
		return upgradeInspection{}, err
	}
	if present {
		summary, err := evidence.InspectFormat(options.evidenceFile)
		if err != nil {
			return upgradeInspection{}, fmt.Errorf("inspect evidence log: %w", err)
		}
		if summary.FormatVersion != 0 {
			result.Formats.EvidenceLog = integerPointer(summary.FormatVersion)
		}
	}

	config, routes, egressRoutes, _, err := gateway.LoadConfig(options.gatewayConfig)
	if err != nil {
		return upgradeInspection{}, fmt.Errorf("load Gateway configuration: %w", err)
	}
	gatewaySummary, err := gateway.InspectState(config, routes, egressRoutes)
	if err != nil {
		return upgradeInspection{}, fmt.Errorf("inspect Gateway state: %w", err)
	}
	result.RetainedGatewayGrants = gatewaySummary.RetainedGrants
	if gatewaySummary.Present {
		result.Formats.GatewayState = integerPointer(gatewaySummary.FormatVersion)
	}
	receiptSummary, err := gateway.InspectConnectorReceiptFormat(config)
	if err != nil {
		return upgradeInspection{}, fmt.Errorf("inspect connector receipt log: %w", err)
	}
	if receiptSummary.FormatVersion != 0 {
		result.Formats.ConnectorReceiptLog = integerPointer(receiptSummary.FormatVersion)
	}

	if present, err = pathPresent(options.uplinkStateFile); err != nil {
		return upgradeInspection{}, fmt.Errorf("inspect Executor uplink state path: %w", err)
	} else if present {
		summary, err := executoruplink.InspectStateFormat(options.uplinkStateFile)
		if err != nil {
			return upgradeInspection{}, err
		}
		result.Formats.UplinkState = integerPointer(summary.FormatVersion)
	}

	if present, err = pathPresent(options.supervisorStateFile); err != nil {
		return upgradeInspection{}, fmt.Errorf("inspect supervisor state path: %w", err)
	} else if present {
		summary, err := stewardruntime.InspectStateFormat(options.supervisorStateFile)
		if err != nil {
			return upgradeInspection{}, err
		}
		result.Formats.SupervisorState = integerPointer(summary.FormatVersion)
	}
	return result, nil
}

func requiredOrPresent(path string, required bool, label string) (bool, error) {
	present, err := pathPresent(path)
	if err != nil {
		return false, fmt.Errorf("inspect %s path: %w", label, err)
	}
	if !present && required {
		return false, fmt.Errorf("%s is missing while -signed-admission=configured; restore and reconcile current durable state before upgrading", label)
	}
	return present, nil
}

func pathPresent(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func integerPointer(value int) *int {
	copy := value
	return &copy
}

func checkTargetCompatibility(path string, observed observedStateFormats) (*bool, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := nodeclient.ReadBounded(path, maxReleaseManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("read target release manifest: %w", err)
	}
	var manifest releaseManifest
	if err := dsse.DecodeStrictInto(raw, maxReleaseManifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("decode target release manifest: %w", err)
	}
	if manifest.Schema != "steward.release.v2" || manifest.Version == "" || manifest.OS != "linux" ||
		(manifest.Architecture != "amd64" && manifest.Architecture != "arm64") {
		return nil, errors.New("target release manifest has an invalid schema, platform, or state format inventory")
	}
	var files map[string]string
	if len(manifest.Files) == 0 || json.Unmarshal(manifest.Files, &files) != nil || files == nil {
		return nil, errors.New("target release manifest has an invalid files inventory")
	}
	for _, name := range upgradeStateNames {
		rangeValue := manifest.StateFormats.forName(name)
		if rangeValue.ReadMin < 1 || rangeValue.ReadMax < rangeValue.ReadMin ||
			rangeValue.Write < rangeValue.ReadMin || rangeValue.Write > rangeValue.ReadMax {
			return nil, fmt.Errorf("target release manifest has an invalid %s reader/writer range", name)
		}
	}
	versions := map[string]*int{
		"admission_fence":       observed.AdmissionFence,
		"connector_receipt_log": observed.ConnectorReceiptLog,
		"evidence_log":          observed.EvidenceLog,
		"gateway_state":         observed.GatewayState,
		"operation_journal":     observed.OperationJournal,
		"supervisor_state":      observed.SupervisorState,
		"uplink_state":          observed.UplinkState,
	}
	incompatible := make([]string, 0)
	for _, name := range upgradeStateNames {
		if versions[name] == nil {
			continue
		}
		accepted := manifest.StateFormats.forName(name)
		if *versions[name] < accepted.ReadMin || *versions[name] > accepted.ReadMax {
			incompatible = append(incompatible, fmt.Sprintf("%s version %d is outside reader range %d-%d", name, *versions[name], accepted.ReadMin, accepted.ReadMax))
		} else if accepted.Write < *versions[name] {
			incompatible = append(incompatible, fmt.Sprintf("%s version %d would be rewritten by lower writer version %d", name, *versions[name], accepted.Write))
		}
	}
	compatible := len(incompatible) == 0
	if !compatible {
		return &compatible, fmt.Errorf("target release is not state-compatible: %s; choose a compatible release or perform an explicit state migration before activation", strings.Join(incompatible, "; "))
	}
	return &compatible, nil
}

func (formats releaseStateFormats) forName(name string) releaseFormatRange {
	switch name {
	case "admission_fence":
		return formats.AdmissionFence
	case "connector_receipt_log":
		return formats.ConnectorReceiptLog
	case "evidence_log":
		return formats.EvidenceLog
	case "gateway_state":
		return formats.GatewayState
	case "operation_journal":
		return formats.OperationJournal
	case "supervisor_state":
		return formats.SupervisorState
	case "uplink_state":
		return formats.UplinkState
	default:
		return releaseFormatRange{}
	}
}

func drainAction(inspection upgradeInspection) error {
	actions := make([]string, 0, 3)
	if inspection.ActiveFences != 0 {
		actions = append(actions, "destroy active signed workloads with the current release")
	}
	if inspection.PendingOperations != 0 {
		actions = append(actions, "start the current Executor and let journal reconciliation finish")
	}
	if inspection.RetainedGatewayGrants != 0 {
		actions = append(actions, "revoke or destroy retained Gateway grants with the current release")
	}
	return fmt.Errorf("node is not drained: %s, then retry the upgrade check", strings.Join(actions, "; "))
}
