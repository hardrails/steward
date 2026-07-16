package activation

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/ocibundle"
)

func testSHA256(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}

func testRuntimeRef(character byte) string {
	return "executor-" + strings.Repeat(string(character), 64)
}

func validPlan() PlanV1 {
	return PlanV1{
		SchemaVersion: PlanSchemaV1,
		ActivationID:  "activation-7",
		ReleaseDigest: testSHA256('1'),
		PolicyDigest:  testSHA256('2'),
		IntentDigest:  testSHA256('3'),
		Archive: ArchiveV1{
			Digest: testSHA256('4'),
			Bytes:  512 << 20,
		},
		Transport: TransportNodeLocal,
		Canary: CanaryV1{
			Kind: CanaryHermesWorkspaceAuditV1,
		},
		Timeouts: TimeoutsV1{
			PreflightSeconds:   30,
			ImageImportSeconds: 300,
			AdmissionSeconds:   60,
			StartupSeconds:     120,
			CanarySeconds:      180,
			EvidenceSeconds:    30,
		},
	}
}

func mustMarshalPlan(t *testing.T, plan PlanV1) []byte {
	t.Helper()
	raw, err := MarshalPlanV1(plan)
	if err != nil {
		t.Fatalf("MarshalPlanV1() error = %v", err)
	}
	return raw
}

func TestPlanRoundTripAndExactByteDigest(t *testing.T) {
	plan := validPlan()
	raw := mustMarshalPlan(t, plan)

	parsed, err := ParsePlanV1(raw)
	if err != nil {
		t.Fatalf("ParsePlanV1() error = %v", err)
	}
	if parsed != plan {
		t.Fatalf("ParsePlanV1() = %#v, want %#v", parsed, plan)
	}

	digest, err := PlanDigestV1(raw)
	if err != nil {
		t.Fatalf("PlanDigestV1() error = %v", err)
	}
	if digest != dsse.Digest(raw) {
		t.Fatalf("PlanDigestV1() = %q, want %q", digest, dsse.Digest(raw))
	}

	withWhitespace := append(append([]byte(nil), raw...), '\n')
	whitespaceDigest, err := PlanDigestV1(withWhitespace)
	if err != nil {
		t.Fatalf("PlanDigestV1(with whitespace) error = %v", err)
	}
	if whitespaceDigest == digest {
		t.Fatal("exact-byte digest did not change after serialized bytes changed")
	}
}

func TestParsePlanV1RejectsNonExactJSON(t *testing.T) {
	raw := string(mustMarshalPlan(t, validPlan()))
	archiveDigest := testSHA256('4')

	tests := map[string]string{
		"unknown top-level command": strings.TrimSuffix(raw, "}") + `,"command":"sh"}`,
		"unknown top-level url":     strings.TrimSuffix(raw, "}") + `,"url":"https://registry.invalid/x"}`,
		"unknown nested hook": strings.Replace(raw,
			`"kind":"`+CanaryHermesWorkspaceAuditV1+`"`,
			`"kind":"`+CanaryHermesWorkspaceAuditV1+`","hook":"after"`, 1),
		"duplicate top-level field": strings.Replace(raw,
			`"activation_id":"activation-7"`,
			`"activation_id":"activation-7","activation_id":"activation-8"`, 1),
		"duplicate nested field": strings.Replace(raw,
			`"digest":"`+archiveDigest+`"`,
			`"digest":"`+archiveDigest+`","digest":"`+archiveDigest+`"`, 1),
		"case-mismatched field": strings.Replace(raw,
			`"transport":"node_local"`, `"Transport":"node_local"`, 1),
		"trailing value": raw + `{}`,
	}

	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePlanV1([]byte(candidate))
			if !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("ParsePlanV1() error = %v, want ErrInvalidPlan", err)
			}
		})
	}
}

func TestParsePlanV1RejectsOversizeInput(t *testing.T) {
	_, err := ParsePlanV1(bytes.Repeat([]byte{' '}, MaxPlanBytes+1))
	if !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("ParsePlanV1() error = %v, want ErrInvalidPlan", err)
	}
}

func TestPlanValidationRejectsOutOfContractValues(t *testing.T) {
	tests := map[string]func(*PlanV1){
		"wrong schema": func(plan *PlanV1) {
			plan.SchemaVersion = "steward.activation-plan.v2"
		},
		"empty activation id": func(plan *PlanV1) {
			plan.ActivationID = ""
		},
		"oversize activation id": func(plan *PlanV1) {
			plan.ActivationID = strings.Repeat("a", 129)
		},
		"activation id with slash": func(plan *PlanV1) {
			plan.ActivationID = "activation/7"
		},
		"uppercase digest": func(plan *PlanV1) {
			plan.ReleaseDigest = "sha256:" + strings.Repeat("A", 64)
		},
		"digest without algorithm": func(plan *PlanV1) {
			plan.PolicyDigest = strings.Repeat("a", 64)
		},
		"short digest": func(plan *PlanV1) {
			plan.IntentDigest = "sha256:abcd"
		},
		"archive digest without algorithm": func(plan *PlanV1) {
			plan.Archive.Digest = strings.Repeat("a", 64)
		},
		"uppercase archive digest": func(plan *PlanV1) {
			plan.Archive.Digest = "sha256:" + strings.Repeat("A", 64)
		},
		"zero archive size": func(plan *PlanV1) {
			plan.Archive.Bytes = 0
		},
		"oversize archive": func(plan *PlanV1) {
			plan.Archive.Bytes = MaxActivationArchiveBytes + 1
		},
		"remote transport": func(plan *PlanV1) {
			plan.Transport = "registry_pull"
		},
		"arbitrary canary": func(plan *PlanV1) {
			plan.Canary.Kind = "shell_command_v1"
		},
		"zero preflight timeout": func(plan *PlanV1) {
			plan.Timeouts.PreflightSeconds = 0
		},
		"oversize import timeout": func(plan *PlanV1) {
			plan.Timeouts.ImageImportSeconds = MaxStepTimeoutSeconds + 1
		},
		"zero admission timeout": func(plan *PlanV1) {
			plan.Timeouts.AdmissionSeconds = 0
		},
		"zero startup timeout": func(plan *PlanV1) {
			plan.Timeouts.StartupSeconds = 0
		},
		"zero canary timeout": func(plan *PlanV1) {
			plan.Timeouts.CanarySeconds = 0
		},
		"zero evidence timeout": func(plan *PlanV1) {
			plan.Timeouts.EvidenceSeconds = 0
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := validPlan()
			mutate(&plan)
			if err := plan.Validate(); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("Validate() error = %v, want ErrInvalidPlan", err)
			}
			if _, err := MarshalPlanV1(plan); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("MarshalPlanV1() error = %v, want ErrInvalidPlan", err)
			}
		})
	}
}

func TestPlanValidationAcceptsBoundaryValues(t *testing.T) {
	plan := validPlan()
	plan.Archive.Bytes = MaxActivationArchiveBytes
	plan.Timeouts = TimeoutsV1{
		PreflightSeconds:   MinStepTimeoutSeconds,
		ImageImportSeconds: MaxStepTimeoutSeconds,
		AdmissionSeconds:   MinStepTimeoutSeconds,
		StartupSeconds:     MaxStepTimeoutSeconds,
		CanarySeconds:      MinStepTimeoutSeconds,
		EvidenceSeconds:    MaxStepTimeoutSeconds,
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("Validate() boundary error = %v", err)
	}
}

func TestArchiveV1MatchesOCIImporterIdentity(t *testing.T) {
	plan := validPlan()
	identity := ocibundle.ArchiveIdentity(plan.Archive)
	if identity != plan.Archive {
		t.Fatalf("archive identity = %#v, want %#v", identity, plan.Archive)
	}
	if MaxActivationArchiveBytes != ocibundle.DefaultMaxArchiveBytes {
		t.Fatalf("activation archive maximum = %d, want importer maximum %d",
			MaxActivationArchiveBytes, ocibundle.DefaultMaxArchiveBytes)
	}
	raw := string(mustMarshalPlan(t, plan))
	if !strings.Contains(raw, `"archive":{"digest":"`+plan.Archive.Digest+`","bytes":536870912}`) {
		t.Fatalf("plan archive JSON does not use importer identity fields: %s", raw)
	}
}
