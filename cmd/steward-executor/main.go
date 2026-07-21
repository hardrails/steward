// steward-executor is a separate, host-local Docker/gVisor execution service.
// It is control-plane and agent-vendor independent.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/buildinfo"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/executoruplink"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/journal"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/securefile"
	"github.com/hardrails/steward/internal/storagebackend"
	stewarduplink "github.com/hardrails/steward/internal/uplink"
)

func main() {
	version := flag.Bool("version", false, "print the Steward Executor version and exit")
	checkConfig := flag.Bool("check-config", false, "validate configuration and host prerequisites, then exit")
	addr := flag.String("addr", "127.0.0.1:8090", "host:port to listen on")
	dockerSocket := flag.String("docker-socket", "/var/run/docker.sock", "Docker Engine Unix socket")
	tokenFile := flag.String("token-file", "", "path to host-admin executor bearer token (required)")
	operatorTokenFile := flag.String("operator-token-file", "", "optional path to operator executor bearer token")
	observerTokenFile := flag.String("observer-token-file", "", "optional path to observer executor bearer token")
	disableInbound := flag.Bool("disable-inbound-listener", false, "run outbound-only without binding the host-local HTTP API")
	uplinkURL := flag.String("uplink-url", "", "optional control-plane base URL for outbound executor commands")
	uplinkCredentialFile := flag.String("uplink-credential-file", "", "path to versioned executor uplink credential")
	inspectUplinkCredential := flag.Bool("inspect-uplink-credential", false, "validate an uplink credential and print its scope and node ID, then exit")
	uplinkStateFile := flag.String("uplink-state-file", "", "path to durable executor command-fencing state")
	initializeUplinkState := flag.Bool("initialize-uplink-state", false, "initialize a new empty executor uplink fence and exit")
	migrateUplinkStateTenant := flag.String("migrate-uplink-state-v1-tenant", "", "explicitly bind a version-1 uplink fence to this tenant and migrate it to version 2")
	uplinkProtocolVersion := flag.Int("uplink-protocol-version", 0, "executor uplink protocol (0 selects from credential and delivery state)")
	uplinkDeliveryStateFile := flag.String("uplink-delivery-state-file", "", "owner-only durable delivery state required for executor uplink protocol 3 or 4")
	initializeUplinkDeliveryState := flag.Bool("initialize-uplink-delivery-state", false, "initialize node-bound executor uplink delivery state and exit")
	uplinkPollInterval := flag.Duration("uplink-poll-interval", 10*time.Second, "base interval between executor uplink polls")
	uplinkAllowInsecureHTTP := flag.Bool("uplink-allow-insecure-http", false, "explicitly allow plaintext HTTP to a non-loopback uplink")
	uplinkTLSCAFile := flag.String("uplink-tls-ca-file", "", "optional PEM CA bundle for the executor uplink")
	uplinkTLSClientCert := flag.String("uplink-tls-client-cert", "", "optional mTLS client certificate for the executor uplink")
	uplinkTLSClientKey := flag.String("uplink-tls-client-key", "", "optional mTLS client key for the executor uplink")
	uplinkTLSSkipVerify := flag.Bool("uplink-tls-skip-verify", false, "INSECURE: disable executor uplink server certificate verification")
	evidenceUplink := flag.Bool("evidence-uplink", false, "publish signed Executor evidence through the protected control-plane uplink")
	evidenceUplinkControllerInstanceID := flag.String("evidence-uplink-controller-instance-id", "", "control-plane instance identity bound during enrollment")
	evidenceUplinkPollInterval := flag.Duration("evidence-uplink-poll-interval", 30*time.Second, "base interval between Executor evidence uplink polls")
	defaults := executor.DefaultHostPolicy()
	maxMemoryBytes := flag.Int64("max-memory-bytes", defaults.MaxMemoryBytes, "maximum memory bytes for one workload")
	maxCPUMillis := flag.Int64("max-cpu-millis", defaults.MaxCPUMillis, "maximum CPU millicores for one workload")
	maxPIDs := flag.Int64("max-pids", defaults.MaxPIDs, "maximum processes for one workload")
	maxWorkloads := flag.Int("max-workloads", defaults.MaxWorkloads, "maximum executor-managed workloads on this host")
	maxWorkloadsPerTenant := flag.Int("max-workloads-per-tenant", defaults.MaxWorkloadsPerTenant, "maximum executor-managed workloads for one tenant")
	maxTotalMemoryBytes := flag.Int64("max-total-memory-bytes", defaults.MaxTotalMemoryBytes, "maximum memory reserved by all managed workloads and relays")
	maxTotalCPUMillis := flag.Int64("max-total-cpu-millis", defaults.MaxTotalCPUMillis, "maximum CPU millicores reserved by all managed workloads and relays")
	maxTotalPIDs := flag.Int64("max-total-pids", defaults.MaxTotalPIDs, "maximum processes reserved by all managed workloads and relays")
	maxTenantMemoryBytes := flag.Int64("max-tenant-memory-bytes", defaults.MaxTenantMemoryBytes, "maximum memory reserved for one tenant's workloads and relays")
	maxTenantCPUMillis := flag.Int64("max-tenant-cpu-millis", defaults.MaxTenantCPUMillis, "maximum CPU millicores reserved for one tenant's workloads and relays")
	maxTenantPIDs := flag.Int64("max-tenant-pids", defaults.MaxTenantPIDs, "maximum processes reserved for one tenant's workloads and relays")
	nodeLabels := flag.String("node-labels", "", "comma-separated scheduling labels as key=value")
	nodeTaints := flag.String("node-taints", "", "comma-separated scheduling taints; workloads require matching tolerations")
	imagePullRegistry := flag.String("image-pull-registry", "", "optional approved OCI registry host[:port] for missing signed images")
	imagePullAuthFile := flag.String("image-pull-auth-file", "", "optional owner-only steward.registry-auth.v1 secret for the approved registry")
	imagePullTimeout := flag.Duration("image-pull-timeout", 5*time.Minute, "bounded timeout for an opt-in exact image pull")
	allowUnquotaedState := flag.Bool("allow-unquotaed-state-on-dedicated-host", false, "INSECURE on shared hosts: allow persistent Docker volumes without hard byte or inode quotas")
	stateBackendSocket := flag.String("state-backend-socket", "", "quota-enforced storage worker Unix socket")
	stateBackendTokenFile := flag.String("state-backend-token-file", "", "owner-only storage worker bearer token")
	stateVolumeByteLimit := flag.Int64("state-volume-byte-limit", 10<<30, "hard byte limit for each quota-enforced state lineage")
	stateVolumeObjectLimit := flag.Int64("state-volume-object-limit", 1_000_000, "hard object limit for each quota-enforced state lineage")
	admissionPolicyFile := flag.String("admission-policy-file", "", "signed site-policy DSSE file; enables signed admission")
	admissionSiteRootFile := flag.String("admission-site-root-public-key-file", "", "base64 Ed25519 site-root public key")
	admissionSiteRootKeyID := flag.String("admission-site-root-key-id", "", "site-root key ID used by the signed policy")
	admissionNodeID := flag.String("admission-node-id", "", "stable local node ID bound by instance intents and receipts")
	admissionFenceFile := flag.String("admission-fence-file", "/var/lib/steward-executor/admission-fences.bin", "durable admission high-water store")
	initializeAdmissionFence := flag.Bool("initialize-admission-fence", false, "create a new empty admission fence store and exit")
	admissionAllowHostAdmin := flag.Bool("admission-allow-host-admin-intent", false, "allow the host-wide local bearer credential to select an intent tenant")
	admissionJournalFile := flag.String("admission-journal-file", "/var/lib/steward-executor/operation-journal.bin", "durable host mutation journal")
	admissionEvidenceFile := flag.String("admission-evidence-file", "/var/lib/steward-executor/evidence.bin", "signed enforcement receipt chain")
	admissionEvidenceKeyFile := flag.String("admission-evidence-key-file", "", "PKCS#8 PEM Ed25519 node receipt private key")
	admissionEvidenceEpoch := flag.Uint64("admission-evidence-epoch", 1, "receipt key epoch")
	gatewayControlSocket := flag.String("gateway-control-socket", "", "Steward Gateway Unix control socket; enables inference, service, and egress grants")
	gatewayGrantRoot := flag.String("gateway-grant-root", "/run/steward-gateway/grants", "host directory containing per-grant capability sockets")
	relayImage := flag.String("relay-image", "", "immutable steward-relay image reference required with gateway topology")
	relayGID := flag.Int("relay-gid", 0, "host group ID used for per-grant relay socket access")
	flag.Parse()
	if *version {
		fmt.Println("steward-executor " + buildinfo.Resolve())
		return
	}
	oneShotActions := 0
	for _, selected := range []bool{
		*inspectUplinkCredential, *initializeUplinkState, *migrateUplinkStateTenant != "",
		*initializeUplinkDeliveryState, *initializeAdmissionFence,
	} {
		if selected {
			oneShotActions++
		}
	}
	if oneShotActions > 1 {
		slog.Error("credential inspection, state initialization, and migration actions are mutually exclusive")
		os.Exit(2)
	}
	if *inspectUplinkCredential {
		if *uplinkCredentialFile == "" {
			slog.Error("credential inspection requires -uplink-credential-file")
			os.Exit(2)
		}
		metadata, err := stewarduplink.InspectCredential(*uplinkCredentialFile)
		if err != nil {
			slog.Error("inspect executor uplink credential", "err", err)
			os.Exit(2)
		}
		scope := "tenant"
		if metadata.NodeScoped() {
			scope = "node"
		}
		fmt.Printf("%s\n%s\n", scope, metadata.NodeID)
		return
	}
	if *initializeUplinkState {
		if err := executoruplink.InitializeStateStore(*uplinkStateFile); err != nil {
			slog.Error("initialize executor uplink state", "err", err)
			os.Exit(2)
		}
		fmt.Println("initialized executor uplink state " + *uplinkStateFile)
		return
	}
	if *migrateUplinkStateTenant != "" {
		backup, err := executoruplink.MigrateStateStoreV1ToV2(*uplinkStateFile, *migrateUplinkStateTenant)
		if err != nil {
			slog.Error("migrate executor uplink state", "err", err)
			os.Exit(2)
		}
		fmt.Printf("migrated executor uplink state %s; preserved version-1 backup %s\n", *uplinkStateFile, backup)
		return
	}
	if *initializeUplinkDeliveryState {
		if *uplinkDeliveryStateFile == "" || *admissionNodeID == "" {
			slog.Error("delivery-state initialization requires -uplink-delivery-state-file and -admission-node-id")
			os.Exit(2)
		}
		if err := executoruplink.InitializeDeliveryStore(*uplinkDeliveryStateFile, *admissionNodeID); err != nil {
			slog.Error("initialize executor uplink delivery state", "err", err)
			os.Exit(2)
		}
		fmt.Println("initialized executor uplink delivery state " + *uplinkDeliveryStateFile)
		return
	}
	if *initializeAdmissionFence {
		if err := admission.InitializeFenceStore(*admissionFenceFile); err != nil {
			slog.Error("initialize admission fence", "err", err)
			os.Exit(2)
		}
		fmt.Println("initialized admission fence " + *admissionFenceFile)
		return
	}
	if *tokenFile == "" {
		slog.Error("-token-file is required")
		os.Exit(2)
	}
	token, err := nodeclient.ReadToken(*tokenFile)
	if err != nil {
		slog.Error("read executor token", "err", err)
		os.Exit(2)
	}
	localCredentials := []executor.LocalCredential{{
		ID: "host-admin", Role: executor.LocalRoleHostAdmin, Token: token,
	}}
	for _, configured := range []struct {
		path string
		id   string
		role executor.LocalRole
	}{
		{path: *operatorTokenFile, id: "operator", role: executor.LocalRoleOperator},
		{path: *observerTokenFile, id: "observer", role: executor.LocalRoleObserver},
	} {
		if configured.path == "" {
			continue
		}
		value, err := nodeclient.ReadToken(configured.path)
		if err != nil {
			slog.Error("read scoped executor token", "role", configured.role, "err", err)
			os.Exit(2)
		}
		localCredentials = append(localCredentials, executor.LocalCredential{
			ID: configured.id, Role: configured.role, Token: value,
		})
	}
	docker := executor.NewDockerHTTP(*dockerSocket)
	available, err := docker.RuntimeAvailable(context.Background(), "runsc")
	if err != nil {
		slog.Error("check Docker runsc runtime", "err", err)
		os.Exit(2)
	}
	if !available {
		slog.Error("Docker runtime runsc is required; install and configure gVisor before starting")
		os.Exit(2)
	}
	policy := executor.HostPolicy{
		MaxMemoryBytes:        *maxMemoryBytes,
		MaxCPUMillis:          *maxCPUMillis,
		MaxPIDs:               *maxPIDs,
		MaxWorkloads:          *maxWorkloads,
		MaxWorkloadsPerTenant: *maxWorkloadsPerTenant,
		MaxTotalMemoryBytes:   *maxTotalMemoryBytes,
		MaxTotalCPUMillis:     *maxTotalCPUMillis,
		MaxTotalPIDs:          *maxTotalPIDs,
		MaxTenantMemoryBytes:  *maxTenantMemoryBytes,
		MaxTenantCPUMillis:    *maxTenantCPUMillis,
		MaxTenantPIDs:         *maxTenantPIDs,
	}
	schedulingLabels, schedulingTaints, err := parseSchedulingAttributes(*nodeLabels, *nodeTaints)
	if err != nil {
		slog.Error("configure node scheduling attributes", "err", err)
		os.Exit(2)
	}
	server, err := executor.NewServerWithLocalCredentials(docker, localCredentials, policy, slog.Default())
	if err != nil {
		slog.Error("configure executor", "err", err)
		os.Exit(2)
	}
	var operationJournal *journal.Journal
	var receiptLog *evidence.Log
	var receiptPrivate ed25519.PrivateKey
	var commandPolicy *admission.SitePolicy
	var gatewayControlClient *gateway.ControlClient
	stateSnapshots := false
	secureExecutor := false
	secureNodeID := ""
	admissionRequested := *admissionPolicyFile != "" || *admissionSiteRootFile != "" ||
		*admissionSiteRootKeyID != "" || *admissionNodeID != "" || *admissionEvidenceKeyFile != "" ||
		*admissionAllowHostAdmin || *allowUnquotaedState || *stateBackendSocket != "" || *stateBackendTokenFile != "" ||
		*gatewayControlSocket != "" || *relayImage != "" || *relayGID != 0 ||
		*imagePullRegistry != "" || *imagePullAuthFile != ""
	if admissionRequested {
		if *admissionPolicyFile == "" || *admissionSiteRootFile == "" || *admissionSiteRootKeyID == "" ||
			*admissionNodeID == "" || *admissionEvidenceKeyFile == "" {
			slog.Error("signed admission requires policy, site-root key and ID, node ID, and evidence key")
			os.Exit(2)
		}
		policyEnvelope, err := readSecureArtifact(*admissionPolicyFile, false, 1<<20)
		if err != nil {
			slog.Error("read signed site policy", "err", err)
			os.Exit(2)
		}
		siteRoot, err := readEd25519PublicKey(*admissionSiteRootFile)
		if err != nil {
			slog.Error("read admission site-root public key", "err", err)
			os.Exit(2)
		}
		verifiedPolicy, err := admission.VerifySitePolicy(policyEnvelope, map[string]ed25519.PublicKey{
			*admissionSiteRootKeyID: siteRoot,
		})
		if err != nil {
			slog.Error("verify signed site policy", "err", err)
			os.Exit(2)
		}
		if *allowUnquotaedState && len(verifiedPolicy.Policy.Tenants) != 1 {
			slog.Error("unquotaed persistent state requires a signed site policy with exactly one tenant")
			os.Exit(2)
		}
		if *allowUnquotaedState && (*stateBackendSocket != "" || *stateBackendTokenFile != "") {
			slog.Error("quota-enforced and unquotaed persistent state modes are mutually exclusive")
			os.Exit(2)
		}
		registryAuth := ""
		configuredImagePullTimeout := time.Duration(0)
		if *imagePullRegistry != "" || *imagePullAuthFile != "" {
			if *imagePullRegistry == "" {
				slog.Error("image pull authentication requires an approved registry")
				os.Exit(2)
			}
			configuredImagePullTimeout = *imagePullTimeout
			if *imagePullAuthFile != "" {
				raw, err := readSecureArtifact(*imagePullAuthFile, true, 64<<10)
				if err != nil {
					slog.Error("read image pull authentication", "err", err)
					os.Exit(2)
				}
				registryAuth, err = executor.EncodeRegistryAuth(raw, *imagePullRegistry)
				if err != nil {
					slog.Error("validate image pull authentication", "err", err)
					os.Exit(2)
				}
			}
		}
		var stateBackend storagebackend.Backend
		if *stateBackendSocket != "" || *stateBackendTokenFile != "" {
			if *stateBackendSocket == "" || *stateBackendTokenFile == "" || *stateVolumeByteLimit <= 0 || *stateVolumeObjectLimit <= 0 {
				slog.Error("quota-enforced state requires socket, token file, and positive byte and object limits")
				os.Exit(2)
			}
			stateToken, err := nodeclient.ReadToken(*stateBackendTokenFile)
			if err != nil {
				slog.Error("read storage backend token", "err", err)
				os.Exit(2)
			}
			stateBackend, err = storagebackend.NewUnixClient(*stateBackendSocket, stateToken)
			if err != nil {
				slog.Error("configure storage backend client", "err", err)
				os.Exit(2)
			}
			stateSnapshots = true
		}
		receiptPrivate, err = readEd25519PrivateKey(*admissionEvidenceKeyFile)
		if err != nil {
			slog.Error("read evidence private key", "err", err)
			os.Exit(2)
		}
		fences, err := admission.OpenFenceStore(*admissionFenceFile)
		if err != nil {
			slog.Error("open admission fence store", "err", err)
			os.Exit(2)
		}
		if *checkConfig {
			operationJournal, err = journal.OpenForValidation(*admissionJournalFile)
		} else {
			operationJournal, err = journal.Open(*admissionJournalFile)
		}
		if err != nil {
			slog.Error("open operation journal", "err", err)
			os.Exit(2)
		}
		defer operationJournal.Close()
		if *checkConfig {
			receiptLog, err = evidence.OpenForValidation(
				*admissionEvidenceFile, receiptPrivate.Public().(ed25519.PublicKey), *admissionNodeID, *admissionEvidenceEpoch,
			)
		} else {
			receiptLog, err = evidence.Open(*admissionEvidenceFile, receiptPrivate, *admissionNodeID, *admissionEvidenceEpoch)
		}
		if err != nil {
			slog.Error("open evidence log", "err", err)
			os.Exit(2)
		}
		defer receiptLog.Close()
		var topology executor.TopologyDocker
		var gatewayControl executor.GatewayControl
		configuredGrantRoot := ""
		if *gatewayControlSocket != "" || *relayImage != "" || *relayGID != 0 {
			if *gatewayControlSocket == "" || *relayImage == "" || *relayGID <= 0 {
				slog.Error("gateway topology requires control socket, immutable relay image, and positive relay GID")
				os.Exit(2)
			}
			client, err := gateway.NewControlClient(*gatewayControlSocket)
			if err != nil {
				slog.Error("configure gateway control client", "err", err)
				os.Exit(2)
			}
			gatewayControlClient = client
			topology, gatewayControl = docker, client
			configuredGrantRoot = *gatewayGrantRoot
		}
		if err := server.EnableSecureAdmission(executor.SecureAdmissionConfig{
			PolicyEnvelope: policyEnvelope,
			SiteRoots: map[string]ed25519.PublicKey{
				*admissionSiteRootKeyID: siteRoot,
			},
			NodeID: *admissionNodeID, Fences: fences, Journal: operationJournal, Evidence: receiptLog,
			AllowHostAdminIntent:               *admissionAllowHostAdmin,
			AllowUnquotaedStateOnDedicatedHost: *allowUnquotaedState,
			StateBackend:                       stateBackend,
			StateVolumeByteLimit:               selectedStateLimit(stateBackend, *stateVolumeByteLimit),
			StateVolumeObjectLimit:             selectedStateLimit(stateBackend, *stateVolumeObjectLimit),
			Topology:                           topology, Gateway: gatewayControl, RelayImage: *relayImage,
			GrantRoot: configuredGrantRoot, RelayGID: *relayGID,
			ImagePullRegistry: *imagePullRegistry, RegistryAuth: registryAuth,
			ImagePullTimeout: configuredImagePullTimeout,
		}); err != nil {
			slog.Error("configure signed admission", "err", err)
			os.Exit(2)
		}
		if *checkConfig && len(operationJournal.Pending()) != 0 {
			slog.Error("executor configuration is valid but the operation journal has pending work; normal startup will run in degraded containment mode")
			os.Exit(2)
		}
		if *allowUnquotaedState {
			slog.Warn("unquotaed persistent state is enabled; this mode is only safe on a dedicated single-tenant host")
		}
		commandPolicy = &verifiedPolicy.Policy
		secureExecutor = true
		secureNodeID = *admissionNodeID
	}
	handler := server.Handler()
	var schedulingObservation *controlprotocol.ExecutorSchedulingObservationV1
	if secureNodeID != "" {
		runtimeOverhead := executor.RuntimeOverheadResources()
		schedulingObservation = &controlprotocol.ExecutorSchedulingObservationV1{
			SchemaVersion: controlprotocol.ExecutorSchedulingSchemaV1,
			NodeID:        secureNodeID, CredentialScope: "node", OS: "linux",
			Architecture: runtime.GOARCH, Isolation: controlprotocol.ExecutorSchedulingIsolationGVisor,
			Labels: schedulingLabels, Taints: schedulingTaints,
			Policy: controlprotocol.ExecutorSchedulingPolicyV1{
				PerWorkload: controlprotocol.ExecutorSchedulingResourcesV1{
					MemoryBytes: policy.MaxMemoryBytes, CPUMillis: policy.MaxCPUMillis,
					PIDs: policy.MaxPIDs, Workloads: 1,
				},
				Host: controlprotocol.ExecutorSchedulingResourcesV1{
					MemoryBytes: policy.MaxTotalMemoryBytes, CPUMillis: policy.MaxTotalCPUMillis,
					PIDs: policy.MaxTotalPIDs, Workloads: int64(policy.MaxWorkloads),
				},
				Tenant: controlprotocol.ExecutorSchedulingResourcesV1{
					MemoryBytes: policy.MaxTenantMemoryBytes, CPUMillis: policy.MaxTenantCPUMillis,
					PIDs: policy.MaxTenantPIDs, Workloads: int64(policy.MaxWorkloadsPerTenant),
				},
				RuntimeOverhead: controlprotocol.ExecutorSchedulingResourcesV1{
					MemoryBytes: runtimeOverhead.MemoryBytes, CPUMillis: runtimeOverhead.CPUMillis,
					PIDs: runtimeOverhead.PIDs,
				},
			},
		}
		if err := schedulingObservation.Validate(); err != nil {
			slog.Error("validate node scheduling observation", "err", err)
			os.Exit(2)
		}
	}
	var poller *executoruplink.Poller
	var evidencePublisher *executoruplink.EvidencePublisher
	if *uplinkURL != "" {
		if *uplinkCredentialFile == "" || *uplinkStateFile == "" {
			slog.Error("-uplink-credential-file and -uplink-state-file are required with -uplink-url")
			os.Exit(2)
		}
		uplinkMetadata, err := stewarduplink.InspectCredential(*uplinkCredentialFile)
		if err != nil {
			slog.Error("inspect executor uplink credential", "err", err)
			os.Exit(2)
		}
		var publishedScheduling *controlprotocol.ExecutorSchedulingObservationV1
		var schedulingProvider func(context.Context) (*controlprotocol.ExecutorSchedulingObservationV1, error)
		if uplinkMetadata.NodeScoped() {
			publishedScheduling = schedulingObservation
			if schedulingObservation != nil {
				schedulingProvider = func(ctx context.Context) (*controlprotocol.ExecutorSchedulingObservationV1, error) {
					images, err := docker.CachedImageConfigDigests(ctx)
					if err != nil {
						return nil, err
					}
					observation := *schedulingObservation
					observation.Labels = append([]controlprotocol.ExecutorSchedulingLabelV1{}, schedulingObservation.Labels...)
					observation.Taints = append([]string{}, schedulingObservation.Taints...)
					observation.CachedImageConfigDigests = images
					return &observation, nil
				}
			}
		}
		state, err := executoruplink.LoadStateStore(*uplinkStateFile)
		if err != nil {
			slog.Error("load executor uplink state", "err", err)
			os.Exit(2)
		}
		var deliveryState *executoruplink.DeliveryStore
		if *uplinkDeliveryStateFile != "" {
			if secureNodeID == "" {
				slog.Error("executor uplink delivery state requires signed admission and -admission-node-id")
				os.Exit(2)
			}
			deliveryState, err = executoruplink.LoadDeliveryStore(*uplinkDeliveryStateFile, secureNodeID)
			if err != nil {
				slog.Error("load executor uplink delivery state", "err", err)
				os.Exit(2)
			}
		}
		httpClient, err := stewarduplink.NewHTTPClient(stewarduplink.TLSConfig{
			CAFile: *uplinkTLSCAFile, ClientCertFile: *uplinkTLSClientCert,
			ClientKeyFile: *uplinkTLSClientKey, SkipVerify: *uplinkTLSSkipVerify,
		})
		if err != nil {
			slog.Error("configure executor uplink TLS", "err", err)
			os.Exit(2)
		}
		if *uplinkTLSSkipVerify {
			slog.Warn("executor uplink TLS verification is disabled")
		}
		parsedUplink, err := url.Parse(*uplinkURL)
		if err != nil {
			slog.Error("parse executor uplink URL", "err", err)
			os.Exit(2)
		}
		poller, err = executoruplink.NewPoller(executoruplink.Config{
			BaseURL: *uplinkURL, CredentialPath: *uplinkCredentialFile,
			PollInterval: *uplinkPollInterval, AllowInsecureHTTP: *uplinkAllowInsecureHTTP,
			HTTPClient: httpClient, Handler: handler, LocalToken: token, State: state,
			Logger: slog.Default(), SecureExecutor: secureExecutor, SecureNodeID: secureNodeID,
			ProtectedTransport: parsedUplink.Scheme == "https" && !*uplinkTLSSkipVerify,
			CommandPolicy:      commandPolicy, ProtocolVersion: *uplinkProtocolVersion,
			DeliveryState: deliveryState, GatewayControl: gatewayControlClient,
			StateSnapshots: stateSnapshots,
			ValidateOnly:   *checkConfig, Scheduling: publishedScheduling,
			SchedulingProvider: schedulingProvider,
		})
		if err != nil {
			slog.Error("configure executor uplink", "err", err)
			os.Exit(2)
		}
		if *evidenceUplink {
			if *evidenceUplinkControllerInstanceID == "" {
				slog.Error("-evidence-uplink-controller-instance-id is required with -evidence-uplink")
				os.Exit(2)
			}
			evidencePublisher, err = executoruplink.NewEvidencePublisher(executoruplink.EvidencePublisherConfig{
				BaseURL: *uplinkURL, CredentialPath: *uplinkCredentialFile,
				ControllerInstanceID: *evidenceUplinkControllerInstanceID,
				PollInterval:         *evidenceUplinkPollInterval,
				HTTPClient:           httpClient, Logger: slog.Default(),
				Log: receiptLog, PrivateKey: receiptPrivate,
				SecureExecutor: secureExecutor, SecureNodeID: secureNodeID,
				ProtectedTransport: parsedUplink.Scheme == "https" && !*uplinkTLSSkipVerify,
			})
			if err != nil {
				slog.Error("configure Executor evidence uplink", "err", err)
				os.Exit(2)
			}
		} else if *evidenceUplinkControllerInstanceID != "" {
			slog.Error("-evidence-uplink-controller-instance-id requires -evidence-uplink")
			os.Exit(2)
		}
	} else if *uplinkCredentialFile != "" || *uplinkStateFile != "" || *uplinkProtocolVersion != 0 ||
		*uplinkDeliveryStateFile != "" || *uplinkAllowInsecureHTTP ||
		*uplinkTLSCAFile != "" || *uplinkTLSClientCert != "" || *uplinkTLSClientKey != "" || *uplinkTLSSkipVerify ||
		*evidenceUplink || *evidenceUplinkControllerInstanceID != "" {
		slog.Error("executor uplink options require -uplink-url")
		os.Exit(2)
	}
	if *disableInbound && poller == nil {
		slog.Error("-disable-inbound-listener requires -uplink-url; otherwise the executor has no control channel")
		os.Exit(2)
	}
	// Reaching this point means the same startup path has already opened and
	// validated the token, Docker socket/runsc runtime, host policy, and -- when
	// uplink is enabled -- durable fence, TLS files, and credential (NewPoller loads
	// it). The dry run returns only after those resources are proven readable by the
	// real process identity; it merely skips polling and listener binding below.
	if *checkConfig {
		fmt.Println("executor configuration valid")
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if secureExecutor {
		reconcileContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
		report, err := server.Reconcile(reconcileContext)
		cancel()
		if err != nil {
			slog.Warn("initial executor reconciliation is incomplete; starting in degraded containment mode", "err", err,
				"checked", report.Checked, "changed", report.Changed,
				"revoked", report.Revoked, "failures", len(report.Failures)+report.DroppedFailures)
		}
		go func() {
			if err := server.RunReconciler(ctx, 30*time.Second); err != nil && ctx.Err() == nil {
				slog.Error("executor reconciler stopped", "err", err)
				stop()
			}
		}()
	}
	if poller != nil {
		go poller.Run(ctx)
	}
	if evidencePublisher != nil {
		go evidencePublisher.Run(ctx)
	}
	if *disableInbound {
		<-ctx.Done()
		return
	}
	httpServer := &http.Server{
		Addr: *addr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown executor", "err", err)
		}
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("serve executor", "err", err)
			os.Exit(1)
		}
	}
}

func selectedStateLimit(backend storagebackend.Backend, value int64) int64 {
	if backend == nil {
		return 0
	}
	return value
}

func parseSchedulingAttributes(
	labelsRaw, taintsRaw string,
) ([]controlprotocol.ExecutorSchedulingLabelV1, []string, error) {
	labelValues := make(map[string]string)
	if labelsRaw != "" {
		for _, item := range strings.Split(labelsRaw, ",") {
			key, value, found := strings.Cut(item, "=")
			if !found || key == "" || value == "" {
				return nil, nil, errors.New("node labels must use comma-separated key=value entries")
			}
			if !controlprotocol.ValidSchedulingAttribute(key) ||
				!controlprotocol.ValidSchedulingAttribute(value) {
				return nil, nil, fmt.Errorf("node label %q contains an invalid key or value", item)
			}
			if _, duplicate := labelValues[key]; duplicate {
				return nil, nil, fmt.Errorf("node label %q is duplicated", key)
			}
			labelValues[key] = value
		}
	}
	labelKeys := make([]string, 0, len(labelValues))
	for key := range labelValues {
		labelKeys = append(labelKeys, key)
	}
	sort.Strings(labelKeys)
	labels := make([]controlprotocol.ExecutorSchedulingLabelV1, 0, len(labelKeys))
	for _, key := range labelKeys {
		labels = append(labels, controlprotocol.ExecutorSchedulingLabelV1{Key: key, Value: labelValues[key]})
	}
	taints := []string{}
	if taintsRaw != "" {
		taints = strings.Split(taintsRaw, ",")
		sort.Strings(taints)
		for index, value := range taints {
			if !controlprotocol.ValidSchedulingAttribute(value) {
				return nil, nil, fmt.Errorf("node taint %q contains invalid characters", value)
			}
			if index > 0 && taints[index-1] == value {
				return nil, nil, errors.New("node taints must be unique")
			}
		}
	}
	return labels, taints, nil
}

func readSecureArtifact(path string, secret bool, limit int64) ([]byte, error) {
	permissions := securefile.TrustFile
	if secret {
		permissions = securefile.OwnerOnly
	}
	return securefile.Read(path, limit, permissions)
}

func readEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := readSecureArtifact(path, false, 16<<10)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("public key must be base64 Ed25519")
	}
	return ed25519.PublicKey(decoded), nil
}

func readEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readSecureArtifact(path, true, 16<<10)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("private key must contain one PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return private, nil
}
