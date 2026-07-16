package main

import (
	"testing"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestActivationWorkspaceCapacityCoversMaximumBoundedInventory(t *testing.T) {
	fixed := map[string]int64{
		activationstore.ReleaseFileName:                 agentrelease.MaxEnvelopeBytes,
		activationstore.PolicyFileName:                  maxArtifactBytes,
		activationstore.IntentFileName:                  maxArtifactBytes,
		activationstore.PlanFileName:                    activation.MaxPlanBytes,
		activationstore.AdmissionFileName:               maxArtifactBytes,
		activationstore.ServiceTrustFileName:            maxServiceTrustBytes,
		activationstore.CanaryRequestFileName:           agentrelease.MaxCanaryRequestBytes,
		activationstore.CanaryChallengeFileName:         activation.MaxChallengeBytes,
		activationstore.CanaryTaskFileName:              maxTaskBundleBytes,
		activationstore.CanarySubmitFileName:            maxArtifactBytes,
		activationstore.CanaryStatusFileName:            maxArtifactBytes,
		activationstore.CanaryResultFileName:            activation.MaxCanaryResultBytes,
		activationstore.ExecutorBaselineWitnessFileName: controlprotocol.MaxExecutorEvidenceJSONBytes,
		activationstore.ExecutorBeginFileName:           activation.MaxExecutorCheckpointBytes,
		activationstore.ExecutorCheckpointFileName:      activation.MaxExecutorCheckpointBytes,
		activationstore.ExecutorDeltaFileName:           activation.MaxExecutorDeltaBytes,
		activationstore.ExecutorFinalWitnessFileName:    controlprotocol.MaxExecutorEvidenceJSONBytes,
		activationstore.GatewayTaskReceiptsFileName:     connectorledger.MaxPortableTaskEvidenceBytes,
		activationstore.ProofFileName:                   activation.MaxProofBytes,
	}
	if len(fixed) != 19 {
		t.Fatalf("bounded fixed small-artifact inventory has %d entries, want 19", len(fixed))
	}
	if activationstore.MaxSmallArtifactBytes != activation.MaxExecutorDeltaBytes {
		t.Fatalf(
			"individual artifact cap = %d, want Executor delta cap %d",
			activationstore.MaxSmallArtifactBytes,
			activation.MaxExecutorDeltaBytes,
		)
	}

	required := int64(0)
	for name, maximum := range fixed {
		if maximum < 0 || maximum > activationstore.MaxSmallArtifactBytes {
			t.Fatalf(
				"artifact %q maximum = %d, outside individual cap %d",
				name, maximum, activationstore.MaxSmallArtifactBytes,
			)
		}
		required += maximum
	}
	// The lock and OCI archive consume entries but not small-artifact bytes.
	stateSlots := activationstore.MaxWorkspaceEntries - len(fixed) - 2
	if stateSlots != 27 {
		t.Fatalf("state checkpoint slots = %d, want 27", stateSlots)
	}
	required += int64(stateSlots) * int64(activation.MaxStateBytes)

	const aggregateCeiling = int64(40 << 20)
	if activationstore.MaxSmallFilesBytes != aggregateCeiling {
		t.Fatalf(
			"aggregate small-artifact cap = %d, want explicit %d-byte ceiling",
			activationstore.MaxSmallFilesBytes, aggregateCeiling,
		)
	}
	if required > activationstore.MaxSmallFilesBytes {
		t.Fatalf(
			"maximum bounded activation inventory needs %d bytes, cap is %d",
			required, activationstore.MaxSmallFilesBytes,
		)
	}
}
