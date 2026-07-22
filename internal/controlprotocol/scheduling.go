package controlprotocol

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	ExecutorSchedulingSchemaV1        = "steward.executor-scheduling.v1"
	MaxExecutorSchedulingBytes        = 16 << 10
	MaxExecutorSchedulingLabels       = 32
	MaxExecutorSchedulingTaints       = 32
	MaxExecutorSchedulingImages       = 128
	MaxExecutorSchedulingAttribute    = 128
	ExecutorSchedulingIsolationGVisor = "gvisor"
	RuntimeAssuranceSchemaV1          = "steward.runtime-assurance.v1"
	RuntimeAssuranceSharedHost        = "shared-host-hardened"
	RuntimeAssuranceDedicatedHost     = "dedicated-host-hardened"
	RuntimeAssuranceStateEphemeral    = "ephemeral-only"
	RuntimeAssuranceStateQuota        = "quota-enforced"
	RuntimeAssuranceStateDedicated    = "unquotaed-dedicated"
)

// ExecutorSchedulingResourcesV1 is one finite CPU, memory, process, and
// workload-slot budget. Counts use int64 so the wire contract has the same
// range on every supported architecture.
type ExecutorSchedulingResourcesV1 struct {
	MemoryBytes int64 `json:"memory_bytes"`
	CPUMillis   int64 `json:"cpu_millis"`
	PIDs        int64 `json:"pids"`
	Workloads   int64 `json:"workloads"`
}

// ExecutorSchedulingPolicyV1 mirrors the startup-only limits enforced by
// Executor. It is an observation, never authority to exceed local policy.
type ExecutorSchedulingPolicyV1 struct {
	PerWorkload     ExecutorSchedulingResourcesV1 `json:"per_workload"`
	Host            ExecutorSchedulingResourcesV1 `json:"host"`
	Tenant          ExecutorSchedulingResourcesV1 `json:"tenant"`
	RuntimeOverhead ExecutorSchedulingResourcesV1 `json:"runtime_overhead"`
}

type ExecutorSchedulingLabelV1 struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RuntimeAssuranceV1 is a digestible statement of the security-relevant
// Executor configuration that produced a scheduling observation. It is not
// remote attestation: the node remains an authenticated but untrusted reporter.
// Independently signed pool membership can bind the digest so Control cannot
// silently substitute a weaker configuration for elastic placement.
type RuntimeAssuranceV1 struct {
	SchemaVersion      string `json:"schema_version"`
	Profile            string `json:"profile"`
	Runtime            string `json:"runtime"`
	Isolation          string `json:"isolation"`
	Network            string `json:"network"`
	StateIsolation     string `json:"state_isolation"`
	CredentialBoundary string `json:"credential_boundary"`
	HostAdminIntent    bool   `json:"host_admin_intent"`
}

// ExecutorSchedulingObservationV1 is posted with the node-scoped Executor
// credential. Control supplies observed_at from its own clock.
type ExecutorSchedulingObservationV1 struct {
	SchemaVersion   string `json:"schema_version"`
	NodeID          string `json:"node_id"`
	CredentialScope string `json:"credential_scope"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	Isolation       string `json:"isolation"`
	// BootIdentitySHA256 is supplied by the node's provisioning or measured-boot
	// integration. A configured pool membership must bind this exact value.
	BootIdentitySHA256 string `json:"boot_identity_sha256,omitempty"`
	// SchedulingPolicySHA256 is derived from Policy by Executor and independently
	// recomputed by Control before the observation is retained.
	SchedulingPolicySHA256 string `json:"scheduling_policy_sha256,omitempty"`
	// RuntimeAssuranceSHA256 commits to RuntimeAssurance. Older observations may
	// omit both fields during rolling upgrades, but cannot satisfy a signed
	// required_assurance placement constraint.
	RuntimeAssurance       *RuntimeAssuranceV1         `json:"runtime_assurance,omitempty"`
	RuntimeAssuranceSHA256 string                      `json:"runtime_assurance_sha256,omitempty"`
	Labels                 []ExecutorSchedulingLabelV1 `json:"labels"`
	Taints                 []string                    `json:"taints"`
	// CachedImageConfigDigests is a soft placement observation. Executor still
	// inspects the exact signed image during admission; Control may use this
	// canonical inventory only to avoid an unnecessary image transfer.
	CachedImageConfigDigests []string                   `json:"cached_image_config_digests"`
	Policy                   ExecutorSchedulingPolicyV1 `json:"policy"`
}

func (observation ExecutorSchedulingObservationV1) Validate() error {
	if observation.SchemaVersion != ExecutorSchedulingSchemaV1 ||
		!ValidSchedulingAttribute(observation.NodeID) || observation.CredentialScope != "node" ||
		observation.OS != "linux" || !ValidSchedulingAttribute(observation.Architecture) ||
		observation.Isolation != ExecutorSchedulingIsolationGVisor {
		return errors.New("executor scheduling observation identity is invalid")
	}
	if observation.Labels == nil || len(observation.Labels) > MaxExecutorSchedulingLabels ||
		observation.Taints == nil || len(observation.Taints) > MaxExecutorSchedulingTaints ||
		len(observation.CachedImageConfigDigests) > MaxExecutorSchedulingImages {
		return errors.New("executor scheduling attributes exceed their limits")
	}
	if observation.BootIdentitySHA256 != "" && !ValidSHA256Digest(observation.BootIdentitySHA256) {
		return errors.New("executor boot identity digest is invalid")
	}
	if observation.SchedulingPolicySHA256 != "" {
		digest, err := SchedulingPolicyDigest(observation.Policy)
		if err != nil || observation.SchedulingPolicySHA256 != digest {
			return errors.New("executor scheduling policy digest is invalid")
		}
	}
	if (observation.RuntimeAssurance == nil) != (observation.RuntimeAssuranceSHA256 == "") {
		return errors.New("executor runtime assurance and digest must be present together")
	}
	if observation.RuntimeAssurance != nil {
		digest, err := RuntimeAssuranceDigest(*observation.RuntimeAssurance)
		if err != nil || observation.RuntimeAssuranceSHA256 != digest {
			return errors.New("executor runtime assurance digest is invalid")
		}
	}
	for index, label := range observation.Labels {
		if !ValidSchedulingAttribute(label.Key) || !ValidSchedulingAttribute(label.Value) ||
			index > 0 && observation.Labels[index-1].Key >= label.Key {
			return errors.New("executor scheduling label is invalid")
		}
	}
	if !sort.StringsAreSorted(observation.Taints) {
		return errors.New("executor scheduling taints are not canonical")
	}
	for index, taint := range observation.Taints {
		if !ValidSchedulingAttribute(taint) || index > 0 && observation.Taints[index-1] == taint {
			return errors.New("executor scheduling taint is invalid")
		}
	}
	for index, digest := range observation.CachedImageConfigDigests {
		if !ValidSHA256Digest(digest) ||
			index > 0 && observation.CachedImageConfigDigests[index-1] >= digest {
			return errors.New("executor scheduling image inventory is not canonical")
		}
	}
	if err := observation.Policy.Validate(); err != nil {
		return err
	}
	return nil
}

// RuntimeAssuranceDigest commits to the exact, fixed-schema assurance claim.
func RuntimeAssuranceDigest(assurance RuntimeAssuranceV1) (string, error) {
	if err := assurance.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(assurance)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + fmt.Sprintf("%x", sum[:]), nil
}

func (assurance RuntimeAssuranceV1) Validate() error {
	if assurance.SchemaVersion != RuntimeAssuranceSchemaV1 || assurance.Runtime != "docker" ||
		assurance.Isolation != ExecutorSchedulingIsolationGVisor || assurance.Network != "isolated-bridge" ||
		(assurance.CredentialBoundary != "gateway-only" && assurance.CredentialBoundary != "not-configured") {
		return errors.New("runtime assurance boundary is invalid")
	}
	switch assurance.StateIsolation {
	case RuntimeAssuranceStateEphemeral, RuntimeAssuranceStateQuota:
		if assurance.Profile == RuntimeAssuranceSharedHost && !assurance.HostAdminIntent {
			return nil
		}
	case RuntimeAssuranceStateDedicated:
		// Unquotaed state is never a shared-host assurance.
	}
	if assurance.Profile == RuntimeAssuranceDedicatedHost {
		return nil
	}
	return errors.New("runtime assurance profile is inconsistent with its controls")
}

// SchedulingPolicyDigest commits to the exact fixed-schema resource policy.
// JSON field order is defined by ExecutorSchedulingPolicyV1's struct layout,
// so every Steward component derives the same bytes without a third-party
// canonicalization dependency.
func SchedulingPolicyDigest(policy ExecutorSchedulingPolicyV1) (string, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + fmt.Sprintf("%x", sum[:]), nil
}

func (policy ExecutorSchedulingPolicyV1) Validate() error {
	if !positiveSchedulingResources(policy.PerWorkload, false) ||
		!positiveSchedulingResources(policy.Host, false) ||
		!positiveSchedulingResources(policy.Tenant, false) ||
		!positiveSchedulingResources(policy.RuntimeOverhead, true) {
		return errors.New("executor scheduling policy contains an invalid limit")
	}
	if policy.PerWorkload.Workloads != 1 || policy.RuntimeOverhead.Workloads != 0 ||
		policy.Tenant.Workloads > policy.Host.Workloads ||
		policy.Tenant.MemoryBytes > policy.Host.MemoryBytes ||
		policy.Tenant.CPUMillis > policy.Host.CPUMillis || policy.Tenant.PIDs > policy.Host.PIDs ||
		policy.PerWorkload.CPUMillis > math.MaxInt64/1_000_000 ||
		policy.Host.CPUMillis > math.MaxInt64/1_000_000 ||
		policy.Tenant.CPUMillis > math.MaxInt64/1_000_000 {
		return errors.New("executor scheduling policy is internally inconsistent")
	}
	return nil
}

func positiveSchedulingResources(resources ExecutorSchedulingResourcesV1, allowZeroWorkloads bool) bool {
	if resources.MemoryBytes <= 0 || resources.CPUMillis <= 0 || resources.PIDs <= 0 {
		return false
	}
	if allowZeroWorkloads {
		return resources.Workloads == 0
	}
	return resources.Workloads > 0
}

// ValidSchedulingAttribute defines the one shared vocabulary for node labels,
// taints, and tenant-signed placement constraints. Using the same validator at
// every boundary prevents a valid delegation from requesting an attribute no
// valid node can advertise.
func ValidSchedulingAttribute(value string) bool {
	if value == "" || len(value) > MaxExecutorSchedulingAttribute || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || strings.ContainsRune("._:/-", char) {
			continue
		}
		return false
	}
	return true
}
