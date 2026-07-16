package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/dsse"
)

func TestActivationVerifyOfflineFailureCheckpoints(t *testing.T) {
	fixture := newOfflineActivationFixture(t)

	if err := verifyActivation([]string{"-unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown verify flag accepted")
	}
	missingTrust := []string{
		"-dir", fixture.directory,
		"-gateway-receipt-public-key", fixture.gatewayPublicPath,
	}
	if err := verifyActivation(missingTrust, &bytes.Buffer{}); err == nil {
		t.Fatal("missing verification trust accepted")
	}
	badGateway := verificationArgumentsForDirectory(fixture, fixture.directory)
	badGateway[len(badGateway)-1] = filepath.Join(t.TempDir(), "missing-gateway.pem")
	if err := verifyActivation(badGateway, &bytes.Buffer{}); err == nil {
		t.Fatal("missing Gateway receipt key accepted")
	}
	missingWorkspace := verificationArgumentsForDirectory(
		fixture, filepath.Join(t.TempDir(), "missing-workspace"),
	)
	if err := verifyActivation(missingWorkspace, &bytes.Buffer{}); err == nil {
		t.Fatal("missing verification workspace accepted")
	}

	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "missing proof",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(t, directory, activationstore.ProofFileName)
			},
		},
		{
			name: "invalid proof",
			mutate: func(t *testing.T, directory string) {
				writeActivationFixtureFile(t, directory, activationstore.ProofFileName, []byte("{}"))
			},
		},
		{
			name: "missing state chain",
			mutate: func(t *testing.T, directory string) {
				names, err := filepath.Glob(filepath.Join(directory, "state-*.json"))
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range names {
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "invalid release",
			mutate: func(t *testing.T, directory string) {
				writeActivationFixtureFile(t, directory, activationstore.ReleaseFileName, []byte("{}"))
			},
		},
		{
			name: "release checkpoint after proof ceiling",
			mutate: func(t *testing.T, directory string) {
				proof, err := activation.ParseProofV1(offlineRead(
					t, filepath.Join(directory, activationstore.ProofFileName),
				))
				if err != nil {
					t.Fatal(err)
				}
				completed, err := time.Parse(time.RFC3339Nano, proof.CompletedAt)
				if err != nil {
					t.Fatal(err)
				}
				mutateActivationStateFiles(t, directory, func(
					sequence int,
					state *activation.StateV1,
				) {
					if sequence > 0 {
						state.UpdatedAt = completed.Add(
							time.Duration(sequence) * time.Second,
						).Format(time.RFC3339Nano)
					}
				})
			},
		},
		{
			name: "invalid verified state",
			mutate: func(t *testing.T, directory string) {
				writeActivationFixtureFile(
					t, directory, "state-000000000001.json", []byte("{}"),
				)
			},
		},
		{
			name: "verified intent binding mismatch",
			mutate: func(t *testing.T, directory string) {
				mutateActivationStateFiles(t, directory, func(
					_ int,
					state *activation.StateV1,
				) {
					state.Binding.TenantID = "tenant-b"
				})
			},
		},
		{
			name: "not passed",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(t, directory, "state-000000000011.json")
			},
		},
		{
			name: "proof correlation",
			mutate: func(t *testing.T, directory string) {
				mutateActivationProofFile(t, directory, func(proof *activation.ProofV1) {
					proof.StateDigest = activationTestDigest("f")
				})
			},
		},
		{
			name: "archive tamper",
			mutate: func(t *testing.T, directory string) {
				path := filepath.Join(directory, activationstore.ImageArchiveFileName)
				raw := offlineRead(t, path)
				writeActivationFixturePath(t, path, append(raw, 0))
			},
		},
		{
			name: "missing baseline",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(
					t, directory, activationstore.ExecutorBaselineWitnessFileName,
				)
			},
		},
		{
			name: "invalid baseline",
			mutate: func(t *testing.T, directory string) {
				writeActivationFixtureFile(
					t, directory, activationstore.ExecutorBaselineWitnessFileName,
					[]byte("{}"),
				)
			},
		},
		{
			name: "missing admission",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(t, directory, activationstore.AdmissionFileName)
			},
		},
		{
			name: "invalid admission",
			mutate: func(t *testing.T, directory string) {
				writeActivationFixtureFile(
					t, directory, activationstore.AdmissionFileName, []byte("{}"),
				)
			},
		},
		{
			name: "admission runtime mismatch",
			mutate: func(t *testing.T, directory string) {
				path := filepath.Join(directory, activationstore.AdmissionFileName)
				var admitted permitAdmission
				if err := json.Unmarshal(offlineRead(t, path), &admitted); err != nil {
					t.Fatal(err)
				}
				admitted.RuntimeRef = "executor-" + strings.Repeat("f", 64)
				raw, err := json.Marshal(admitted)
				if err != nil {
					t.Fatal(err)
				}
				writeActivationFixturePath(t, path, raw)
			},
		},
		{
			name: "missing service trust",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(t, directory, activationstore.ServiceTrustFileName)
			},
		},
		{
			name: "missing request",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(t, directory, activationstore.CanaryRequestFileName)
			},
		},
		{
			name: "missing challenge",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(t, directory, activationstore.CanaryChallengeFileName)
			},
		},
		{
			name: "invalid challenge",
			mutate: func(t *testing.T, directory string) {
				writeActivationFixtureFile(
					t, directory, activationstore.CanaryChallengeFileName, []byte("{}"),
				)
			},
		},
		{
			name: "challenge binding mismatch",
			mutate: func(t *testing.T, directory string) {
				mutateActivationChallengeFile(t, directory, func(challenge *activation.CanaryChallengeV1) {
					challenge.ActivationID = "activation-other"
				})
			},
		},
		{
			name: "challenge completion ordering",
			mutate: func(t *testing.T, directory string) {
				proof, err := activation.ParseProofV1(offlineRead(
					t, filepath.Join(directory, activationstore.ProofFileName),
				))
				if err != nil {
					t.Fatal(err)
				}
				completed, err := time.Parse(time.RFC3339Nano, proof.CompletedAt)
				if err != nil {
					t.Fatal(err)
				}
				mutateActivationChallengeFile(t, directory, func(challenge *activation.CanaryChallengeV1) {
					challenge.CreatedAt = completed.Add(time.Second).Format(time.RFC3339Nano)
				})
			},
		},
		{
			name: "missing task",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(t, directory, activationstore.CanaryTaskFileName)
			},
		},
		{
			name: "invalid task",
			mutate: func(t *testing.T, directory string) {
				writeActivationFixtureFile(
					t, directory, activationstore.CanaryTaskFileName, []byte("{}"),
				)
			},
		},
		{
			name: "missing submit",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(t, directory, activationstore.CanarySubmitFileName)
			},
		},
		{
			name: "invalid submit",
			mutate: func(t *testing.T, directory string) {
				writeActivationFixtureFile(
					t, directory, activationstore.CanarySubmitFileName, []byte("{}"),
				)
			},
		},
		{
			name: "submit identity mismatch",
			mutate: func(t *testing.T, directory string) {
				path := filepath.Join(directory, activationstore.CanarySubmitFileName)
				var submit activationSubmitRecord
				if err := json.Unmarshal(offlineRead(t, path), &submit); err != nil {
					t.Fatal(err)
				}
				submit.ReceiptEpoch++
				raw, err := json.Marshal(submit)
				if err != nil {
					t.Fatal(err)
				}
				writeActivationFixturePath(t, path, raw)
			},
		},
		{
			name: "Hermes run mismatch",
			mutate: func(t *testing.T, directory string) {
				path := filepath.Join(directory, activationstore.CanarySubmitFileName)
				var submit activationSubmitRecord
				if err := json.Unmarshal(offlineRead(t, path), &submit); err != nil {
					t.Fatal(err)
				}
				submit.RunID = "run_" + strings.Repeat("f", 32)
				raw, err := json.Marshal(submit)
				if err != nil {
					t.Fatal(err)
				}
				writeActivationFixturePath(t, path, raw)
			},
		},
		{
			name: "missing result",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(t, directory, activationstore.CanaryResultFileName)
			},
		},
		{
			name: "invalid result",
			mutate: func(t *testing.T, directory string) {
				writeActivationFixtureFile(
					t, directory, activationstore.CanaryResultFileName, []byte("{}"),
				)
			},
		},
		{
			name: "missing gateway evidence",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(
					t, directory, activationstore.GatewayTaskReceiptsFileName,
				)
			},
		},
		{
			name: "gateway evidence proof mismatch",
			mutate: func(t *testing.T, directory string) {
				mutateActivationProofFile(t, directory, func(proof *activation.ProofV1) {
					proof.GatewayEvidence.ChainHash = activationTestDigest("f")
				})
			},
		},
		{
			name: "missing Executor begin",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(
					t, directory, activationstore.ExecutorBeginFileName,
				)
			},
		},
		{
			name: "begin proof mismatch",
			mutate: func(t *testing.T, directory string) {
				mutateActivationProofFile(t, directory, func(proof *activation.ProofV1) {
					proof.ExecutorBeginDigest = activationTestDigest("f")
				})
			},
		},
		{
			name: "missing Executor checkpoint",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(
					t, directory, activationstore.ExecutorCheckpointFileName,
				)
			},
		},
		{
			name: "checkpoint proof mismatch",
			mutate: func(t *testing.T, directory string) {
				mutateActivationProofFile(t, directory, func(proof *activation.ProofV1) {
					proof.ExecutorCheckpointDigest = activationTestDigest("f")
				})
			},
		},
		{
			name: "missing Executor delta",
			mutate: func(t *testing.T, directory string) {
				removeActivationArtifact(
					t, directory, activationstore.ExecutorDeltaFileName,
				)
			},
		},
		{
			name: "executor evidence proof mismatch",
			mutate: func(t *testing.T, directory string) {
				mutateActivationProofFile(t, directory, func(proof *activation.ProofV1) {
					proof.ExecutorEvidence.ChainHash = activationTestDigest("f")
					proof.Witness.ChainHash = proof.ExecutorEvidence.ChainHash
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := cloneOwnerOnlyActivationWorkspace(t, fixture.directory)
			test.mutate(t, directory)
			if err := verifyActivation(
				verificationArgumentsForDirectory(fixture, directory),
				&bytes.Buffer{},
			); err == nil {
				t.Fatal("tampered offline activation workspace accepted")
			}
		})
	}
}

func TestVerifyActivationTaskFailureCheckpoints(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*activationTaskFixture)
	}{
		{
			name: "invalid challenge",
			mutate: func(fixture *activationTaskFixture) {
				fixture.challenge.SchemaVersion = "wrong"
			},
		},
		{
			name: "missing admitted authorities",
			mutate: func(fixture *activationTaskFixture) {
				fixture.admitted.TaskAuthorities = nil
			},
		},
		{
			name: "challenge authority set mismatch",
			mutate: func(fixture *activationTaskFixture) {
				fixture.challenge.TaskAuthorities[0].KeyID = "other"
			},
		},
		{
			name: "service trust digest mismatch",
			mutate: func(fixture *activationTaskFixture) {
				fixture.challenge.ServiceTrustDigest = activationTestDigest("f")
			},
		},
		{
			name: "canonical admission mismatch",
			mutate: func(fixture *activationTaskFixture) {
				fixture.challenge.AdmissionDigest = activationTestDigest("f")
			},
		},
		{
			name: "activation binding mismatch",
			mutate: func(fixture *activationTaskFixture) {
				fixture.challenge.ActivationID = "activation-other"
			},
		},
		{
			name: "invalid task wire",
			mutate: func(fixture *activationTaskFixture) {
				fixture.taskRaw = []byte("{}")
			},
		},
		{
			name: "invalid embedded authority",
			mutate: func(fixture *activationTaskFixture) {
				var wire taskBundle
				_ = json.Unmarshal(fixture.taskRaw, &wire)
				wire.Authority.PublicKey = "not-base64"
				fixture.taskRaw, _ = json.Marshal(wire)
			},
		},
		{
			name: "untrusted embedded authority",
			mutate: func(fixture *activationTaskFixture) {
				var wire taskBundle
				_ = json.Unmarshal(fixture.taskRaw, &wire)
				wire.Authority.KeyID = "other-authority"
				fixture.taskRaw, _ = json.Marshal(wire)
			},
		},
		{
			name: "invalid permit base64",
			mutate: func(fixture *activationTaskFixture) {
				var wire taskBundle
				_ = json.Unmarshal(fixture.taskRaw, &wire)
				wire.Permit = "not-base64"
				fixture.taskRaw, _ = json.Marshal(wire)
			},
		},
		{
			name: "invalid signed permit",
			mutate: func(fixture *activationTaskFixture) {
				var wire taskBundle
				_ = json.Unmarshal(fixture.taskRaw, &wire)
				wire.Permit = "e30="
				fixture.taskRaw, _ = json.Marshal(wire)
			},
		},
		{
			name: "invalid service trust",
			mutate: func(fixture *activationTaskFixture) {
				fixture.serviceTrustRaw = []byte("{}")
				fixture.challenge.ServiceTrustDigest = dsse.Digest(fixture.serviceTrustRaw)
			},
		},
		{
			name: "invalid release request recipe",
			mutate: func(fixture *activationTaskFixture) {
				fixture.inputs.release.Release.Canary.Request.Input = "unsupported"
			},
		},
		{
			name: "transport path mismatch",
			mutate: func(fixture *activationTaskFixture) {
				fixture.admitted.ServicePath = "/v1/services/other/"
				raw, _ := json.Marshal(fixture.admitted)
				fixture.challenge.AdmissionDigest = dsse.Digest(raw)
			},
		},
		{
			name: "permit binding mismatch",
			mutate: func(fixture *activationTaskFixture) {
				fixture.inputs.intent.NodeID = "node-b"
				fixture.challenge.NodeID = "node-b"
			},
		},
		{
			name: "permit expired before challenge",
			mutate: func(fixture *activationTaskFixture) {
				fixture.challenge.CreatedAt = fixtureTime().
					Add(20 * time.Minute).Format(time.RFC3339Nano)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newActivationTaskFixture(t)
			test.mutate(&fixture)
			if _, err := verifyActivationTask(
				fixture.taskRaw, fixture.challenge, fixture.admitted,
				fixture.inputs, fixture.serviceTrustRaw, fixture.requestRaw,
			); err == nil {
				t.Fatal("invalid activation task accepted")
			}
		})
	}

	fixture := newActivationTaskFixture(t)
	task, err := verifyActivationTask(
		fixture.taskRaw, fixture.challenge, fixture.admitted,
		fixture.inputs, fixture.serviceTrustRaw, fixture.requestRaw,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyActivationTaskAt(task, "not-a-time"); err == nil {
		t.Fatal("noncanonical Gateway authorization time accepted")
	}
	if err := verifyActivationTaskAt(
		task, fixtureTime().Add(24*time.Hour).Format(time.RFC3339Nano),
	); err == nil {
		t.Fatal("task accepted outside its signed validity interval")
	}
	if slicesEqualTaskPins(
		[]activation.TaskAuthorityPinV1{{KeyID: "a"}},
		nil,
	) {
		t.Fatal("task pin lists with different lengths reported equal")
	}
	if slicesEqualTaskPins(
		[]activation.TaskAuthorityPinV1{{KeyID: "a"}},
		[]activation.TaskAuthorityPinV1{{KeyID: "b"}},
	) {
		t.Fatal("different task pins reported equal")
	}
}

func verificationArgumentsForDirectory(
	fixture offlineActivationFixture,
	directory string,
) []string {
	arguments := append([]string(nil), fixture.verificationArgument...)
	arguments[1] = directory
	return arguments
}

func cloneOwnerOnlyActivationWorkspace(t *testing.T, source string) string {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "activation")
	if err := os.CopyFS(destination, os.DirFS(source)); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(destination, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return os.Chmod(path, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	return destination
}

func removeActivationArtifact(t *testing.T, directory, name string) {
	t.Helper()
	if err := os.Remove(filepath.Join(directory, name)); err != nil {
		t.Fatal(err)
	}
}

func writeActivationFixtureFile(
	t *testing.T,
	directory, name string,
	raw []byte,
) {
	t.Helper()
	writeActivationFixturePath(t, filepath.Join(directory, name), raw)
}

func writeActivationFixturePath(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mutateActivationProofFile(
	t *testing.T,
	directory string,
	mutate func(*activation.ProofV1),
) {
	t.Helper()
	path := filepath.Join(directory, activationstore.ProofFileName)
	proof, err := activation.ParseProofV1(offlineRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	mutate(&proof)
	raw, err := activation.MarshalProofV1(proof)
	if err != nil {
		t.Fatal(err)
	}
	writeActivationFixturePath(t, path, raw)
}

func mutateActivationChallengeFile(
	t *testing.T,
	directory string,
	mutate func(*activation.CanaryChallengeV1),
) {
	t.Helper()
	path := filepath.Join(directory, activationstore.CanaryChallengeFileName)
	challenge, err := activation.ParseChallengeV1(offlineRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	mutate(&challenge)
	raw, err := activation.MarshalChallengeV1(challenge)
	if err != nil {
		t.Fatal(err)
	}
	writeActivationFixturePath(t, path, raw)
}

func mutateActivationStateFiles(
	t *testing.T,
	directory string,
	mutate func(int, *activation.StateV1),
) {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(directory, "state-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for sequence, path := range names {
		state, err := activation.ParseStateV1(offlineRead(t, path))
		if err != nil {
			t.Fatal(err)
		}
		mutate(sequence, &state)
		raw, err := activation.MarshalStateV1(state)
		if err != nil {
			t.Fatal(err)
		}
		writeActivationFixturePath(t, path, raw)
	}
}

func TestActivationCreateFailureCheckpoints(t *testing.T) {
	fixture := newOfflineActivationFixture(t)
	valid := []string{
		"-dir", filepath.Join(t.TempDir(), "activation"),
		"-activation-id", "activation-create-errors",
		"-release", filepath.Join(fixture.directory, activationstore.ReleaseFileName),
		"-policy", filepath.Join(fixture.directory, activationstore.PolicyFileName),
		"-intent", filepath.Join(fixture.directory, activationstore.IntentFileName),
		"-archive", filepath.Join(fixture.directory, activationstore.ImageArchiveFileName),
		"-publisher-public-key", fixture.publisherPublicPath,
		"-publisher-key-id", "publisher-a",
		"-site-root-public-key", fixture.siteRootPublicPath,
		"-site-root-key-id", "site-root",
		"-baseline-witness", filepath.Join(
			fixture.directory, activationstore.ExecutorBaselineWitnessFileName,
		),
		"-witness-public-key", fixture.witnessPublicPath,
	}
	if err := createActivation([]string{"-unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown create flag accepted")
	}
	runCreateFailure := func(t *testing.T, mutate func([]string) []string) {
		t.Helper()
		arguments := append([]string(nil), valid...)
		if err := createActivation(mutate(arguments), &bytes.Buffer{}); err == nil {
			t.Fatal("invalid activation create inputs accepted")
		}
	}
	t.Run("trust", func(t *testing.T) {
		runCreateFailure(t, func(arguments []string) []string {
			return append(arguments, "-publisher-key-id", "")
		})
	})
	t.Run("timeout", func(t *testing.T) {
		runCreateFailure(t, func(arguments []string) []string {
			return append(arguments, "-preflight-timeout", "0s")
		})
	})
	t.Run("missing release", func(t *testing.T) {
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-release", filepath.Join(t.TempDir(), "missing"))
		})
	})
	t.Run("invalid release", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "release.json")
		writeActivationFixturePath(t, path, []byte("{}"))
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-release", path)
		})
	})
	t.Run("missing policy", func(t *testing.T) {
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-policy", filepath.Join(t.TempDir(), "missing"))
		})
	})
	t.Run("missing intent", func(t *testing.T) {
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-intent", filepath.Join(t.TempDir(), "missing"))
		})
	})
	t.Run("invalid activation id", func(t *testing.T) {
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-activation-id", "not valid")
		})
	})
	t.Run("invalid intent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "intent.json")
		writeActivationFixturePath(t, path, []byte("{}"))
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-intent", path)
		})
	})
	t.Run("missing baseline", func(t *testing.T) {
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(
				arguments, "-baseline-witness", filepath.Join(t.TempDir(), "missing"),
			)
		})
	})
	t.Run("invalid baseline", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "baseline.json")
		writeActivationFixturePath(t, path, []byte("{}"))
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-baseline-witness", path)
		})
	})
	t.Run("existing workspace", func(t *testing.T) {
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-dir", fixture.directory)
		})
	})
	t.Run("archive import", func(t *testing.T) {
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-archive", t.TempDir())
		})
	})
	t.Run("archive verification", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "archive.tar")
		writeActivationFixturePath(t, path, []byte("not an OCI archive"))
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-archive", path)
		})
	})
	t.Run("archive identity mismatch", func(t *testing.T) {
		source := filepath.Join(fixture.directory, activationstore.ImageArchiveFileName)
		path := filepath.Join(t.TempDir(), "archive.tar")
		writeActivationFixturePath(t, path, append(offlineRead(t, source), 0))
		runCreateFailure(t, func(arguments []string) []string {
			return replaceFlagValue(arguments, "-archive", path)
		})
	})
	t.Run("generated activation ID", func(t *testing.T) {
		arguments := append([]string(nil), valid...)
		for index := 0; index+1 < len(arguments); index++ {
			if arguments[index] == "-activation-id" {
				arguments = append(arguments[:index], arguments[index+2:]...)
				break
			}
		}
		arguments = replaceFlagValue(
			arguments, "-dir", filepath.Join(t.TempDir(), "generated-id"),
		)
		var output bytes.Buffer
		if err := createActivation(arguments, &output); err != nil {
			t.Fatal(err)
		}
		status := decodeActivationStatus(t, output.Bytes())
		if !strings.HasPrefix(status.ActivationID, "activation-") {
			t.Fatalf("generated activation ID = %q", status.ActivationID)
		}
	})
}

func replaceFlagValue(arguments []string, flagName, value string) []string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == flagName {
			arguments[index+1] = value
			return arguments
		}
	}
	return arguments
}
