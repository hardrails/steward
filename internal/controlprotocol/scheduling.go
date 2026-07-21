package controlprotocol

import (
	"errors"
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

// ExecutorSchedulingObservationV1 is posted with the node-scoped Executor
// credential. Control supplies observed_at from its own clock.
type ExecutorSchedulingObservationV1 struct {
	SchemaVersion   string                      `json:"schema_version"`
	NodeID          string                      `json:"node_id"`
	CredentialScope string                      `json:"credential_scope"`
	OS              string                      `json:"os"`
	Architecture    string                      `json:"architecture"`
	Isolation       string                      `json:"isolation"`
	Labels          []ExecutorSchedulingLabelV1 `json:"labels"`
	Taints          []string                    `json:"taints"`
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
