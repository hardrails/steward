package controlprotocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

type controllerCaptureProtocolFixture struct {
	frames         [][]byte
	statement      ControllerEvidenceCaptureStatementV1
	capture        ControllerEvidenceCaptureV1
	receiptPublic  ed25519.PublicKey
	receiptPrivate ed25519.PrivateKey
	witnessPublic  ed25519.PublicKey
	witnessPrivate ed25519.PrivateKey
}

func TestControllerEvidenceCaptureRoundTripAndPinnedWitness(t *testing.T) {
	fixture := newControllerCaptureProtocolFixture(t)
	if err := fixture.capture.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyControllerEvidenceCaptureV1(fixture.capture, fixture.witnessPublic); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fixture.capture)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeControllerEvidenceCaptureV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Statement != fixture.statement {
		t.Fatalf("decoded statement changed: %#v", decoded.Statement)
	}
	frames, err := decoded.DecodeFrames()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != len(fixture.frames) || !bytes.Equal(frames[0], fixture.frames[0]) {
		t.Fatalf("decoded frames=%d", len(frames))
	}
	frames[0][0] ^= 1
	again, err := decoded.DecodeFrames()
	if err != nil || bytes.Equal(frames[0], again[0]) {
		t.Fatal("decoded frame bytes were not returned as independent copies")
	}

	otherPublic, _ := captureProtocolKey(t)
	if err := VerifyControllerEvidenceCaptureV1(fixture.capture, otherPublic); err == nil {
		t.Fatal("capture verified against an unpinned witness key")
	}
	if err := VerifyControllerEvidenceCaptureV1(fixture.capture, nil); err == nil {
		t.Fatal("capture verified without an independently pinned witness key")
	}

	if fixture.statement.FramesDigest == ExecutorEvidenceFramesDigestV1(fixture.frames) {
		t.Fatal("capture frames reused the executor evidence report digest domain")
	}
	captureStatement, err := ControllerEvidenceCaptureSigningStatementV1(fixture.statement)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentStatement, err := ExecutorEvidenceIdentityProofStatementV1(fixture.statement.IdentityProof.Claim)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(captureStatement, enrollmentStatement) ||
		!bytes.HasPrefix(captureStatement, []byte(controllerEvidenceCaptureWitnessDomainV1)) {
		t.Fatal("capture and enrollment signatures are not purpose-separated")
	}
}

func TestControllerEvidenceCaptureStatementBindsEveryMaterialField(t *testing.T) {
	fixture := newControllerCaptureProtocolFixture(t)
	mutations := map[string]func(*ControllerEvidenceCaptureStatementV1){
		"protocol": func(value *ControllerEvidenceCaptureStatementV1) { value.ProtocolVersion++ },
		"controller": func(value *ControllerEvidenceCaptureStatementV1) {
			value.ControllerInstanceID = "controller-b"
		},
		"capture": func(value *ControllerEvidenceCaptureStatementV1) { value.CaptureID = "capture-b" },
		"node":    func(value *ControllerEvidenceCaptureStatementV1) { value.NodeID = "node-b" },
		"tenant":  func(value *ControllerEvidenceCaptureStatementV1) { value.TenantID = "tenant-b" },
		"runtime": func(value *ControllerEvidenceCaptureStatementV1) {
			value.RuntimeRef = "executor-" + strings.Repeat("b", 64)
		},
		"generation": func(value *ControllerEvidenceCaptureStatementV1) { value.Generation++ },
		"activation": func(value *ControllerEvidenceCaptureStatementV1) { value.ActivationID = "activation-b" },
		"canary command": func(value *ControllerEvidenceCaptureStatementV1) {
			value.CanaryCommandID = "canary-command-b"
		},
		"begin digest": func(value *ControllerEvidenceCaptureStatementV1) {
			value.ActivationBeginDigest = captureProtocolDigest("a")
		},
		"begin sequence": func(value *ControllerEvidenceCaptureStatementV1) {
			value.ActivationBeginSequence++
		},
		"checkpoint digest": func(value *ControllerEvidenceCaptureStatementV1) {
			value.ActivationCheckpointDigest = captureProtocolDigest("b")
		},
		"capsule digest": func(value *ControllerEvidenceCaptureStatementV1) {
			value.CapsuleDigest = captureProtocolDigest("c")
		},
		"policy digest": func(value *ControllerEvidenceCaptureStatementV1) {
			value.PolicyDigest = captureProtocolDigest("d")
		},
		"enrollment proof": func(value *ControllerEvidenceCaptureStatementV1) {
			signature, err := base64.StdEncoding.DecodeString(value.IdentityProof.SignatureBase64)
			if err != nil {
				t.Fatal(err)
			}
			signature[0] ^= 1
			value.IdentityProof.SignatureBase64 = base64.StdEncoding.EncodeToString(signature)
		},
		"baseline head": func(value *ControllerEvidenceCaptureStatementV1) {
			value.BaselineHead.Sequence++
			value.FinalHead.Sequence++
		},
		"final head": func(value *ControllerEvidenceCaptureStatementV1) {
			value.FinalHead.ChainHash = captureProtocolDigest("e")
		},
		"frame count": func(value *ControllerEvidenceCaptureStatementV1) {
			value.FrameCount++
			value.FinalHead.Sequence++
		},
		"frame digest": func(value *ControllerEvidenceCaptureStatementV1) {
			value.FramesDigest = captureProtocolDigest("f")
		},
		"armed time": func(value *ControllerEvidenceCaptureStatementV1) {
			value.ArmedAt = "2026-06-30T23:59:59Z"
		},
		"observed time": func(value *ControllerEvidenceCaptureStatementV1) {
			value.ObservedAt = "2026-07-01T00:00:30Z"
		},
		"sealed time": func(value *ControllerEvidenceCaptureStatementV1) {
			value.SealedAt = "2026-07-01T00:01:30Z"
		},
		"exported time": func(value *ControllerEvidenceCaptureStatementV1) {
			value.ExportedAt = "2026-07-01T00:04:00Z"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneControllerCapture(fixture.capture)
			mutate(&candidate.Statement)
			if err := candidate.Validate(); err == nil {
				t.Fatal("mutated controller statement was accepted")
			}
		})
	}
}

func TestControllerEvidenceCaptureRejectsFrameAndEnvelopeMutation(t *testing.T) {
	fixture := newControllerCaptureProtocolFixture(t)
	mutations := map[string]func(*ControllerEvidenceCaptureV1){
		"payload type": func(value *ControllerEvidenceCaptureV1) { value.PayloadType = ExecutorEvidenceExportPayloadTypeV1 },
		"frame mutation": func(value *ControllerEvidenceCaptureV1) {
			frame, err := base64.StdEncoding.DecodeString(value.SignedFramesBase64[0])
			if err != nil {
				t.Fatal(err)
			}
			frame[len(frame)-1] ^= 1
			value.SignedFramesBase64[0] = base64.StdEncoding.EncodeToString(frame)
		},
		"frame removal": func(value *ControllerEvidenceCaptureV1) {
			value.SignedFramesBase64 = value.SignedFramesBase64[:1]
		},
		"frame insertion": func(value *ControllerEvidenceCaptureV1) {
			value.SignedFramesBase64 = append(value.SignedFramesBase64, value.SignedFramesBase64[0])
		},
		"frame reordering": func(value *ControllerEvidenceCaptureV1) {
			value.SignedFramesBase64[0], value.SignedFramesBase64[1] =
				value.SignedFramesBase64[1], value.SignedFramesBase64[0]
		},
		"frame substitution": func(value *ControllerEvidenceCaptureV1) {
			value.SignedFramesBase64[0] = base64.StdEncoding.EncodeToString(captureProtocolFrame("substitute"))
		},
		"witness key": func(value *ControllerEvidenceCaptureV1) {
			public, _ := captureProtocolKey(t)
			value.WitnessPublicKeyBase64 = base64.StdEncoding.EncodeToString(public)
			value.WitnessPublicKeySHA256 = ExecutorEvidencePublicKeySHA256(public)
		},
		"witness digest": func(value *ControllerEvidenceCaptureV1) {
			value.WitnessPublicKeySHA256 = captureProtocolDigest("b")
		},
		"signature": func(value *ControllerEvidenceCaptureV1) {
			signature, err := base64.StdEncoding.DecodeString(value.SignatureBase64)
			if err != nil {
				t.Fatal(err)
			}
			signature[len(signature)-1] ^= 1
			value.SignatureBase64 = base64.StdEncoding.EncodeToString(signature)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneControllerCapture(fixture.capture)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("mutated capture was accepted")
			}
		})
	}
}

func TestControllerEvidenceCaptureLimitsCanonicalEncodingAndStrictJSON(t *testing.T) {
	fixture := newControllerCaptureProtocolFixture(t)

	for name, frames := range map[string][][]byte{
		"empty":     nil,
		"too many":  repeatedCaptureProtocolFrames(MaxControllerEvidenceCaptureFrames+1, 1),
		"oversized": repeatedCaptureProtocolFrames(9, (64<<10)-4),
		"bad prefix": {
			[]byte{0, 0, 0, 2, 1},
		},
	} {
		t.Run(name, func(t *testing.T) {
			statement := fixture.statement
			statement.FrameCount = uint32(len(frames))
			statement.FinalHead.Sequence = statement.BaselineHead.Sequence + uint64(len(frames))
			statement.FramesDigest = ControllerEvidenceCaptureFramesDigestV1(frames)
			if _, err := SignControllerEvidenceCaptureV1(statement, frames, fixture.witnessPrivate); err == nil {
				t.Fatal("invalid frame collection was signed")
			}
		})
	}
	if _, err := SignControllerEvidenceCaptureV1(fixture.statement, fixture.frames, nil); err == nil {
		t.Fatal("capture signed without a witness private key")
	}

	noncanonical := cloneControllerCapture(fixture.capture)
	frame, err := base64.StdEncoding.DecodeString(noncanonical.SignedFramesBase64[0])
	if err != nil {
		t.Fatal(err)
	}
	noncanonical.SignedFramesBase64[0] = base64.RawStdEncoding.EncodeToString(frame)
	if err := noncanonical.Validate(); err == nil {
		t.Fatal("non-canonical frame base64 was accepted")
	}

	raw, err := json.Marshal(fixture.capture)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"duplicate": []byte(strings.Replace(
			string(raw),
			`"payload_type":`,
			`"payload_type":"duplicate","payload_type":`,
			1,
		)),
		"unknown":   []byte(strings.TrimSuffix(string(raw), "}") + `,"unexpected":true}`),
		"trailing":  append(append([]byte(nil), raw...), []byte(` {}`)...),
		"oversized": append(append([]byte(nil), raw...), make([]byte, MaxControllerEvidenceCaptureJSONBytes)...),
		"null frames": []byte(strings.Replace(
			string(raw),
			`"signed_frames_base64":["`+fixture.capture.SignedFramesBase64[0]+`","`+fixture.capture.SignedFramesBase64[1]+`"]`,
			`"signed_frames_base64":null`,
			1,
		)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeControllerEvidenceCaptureV1(candidate); err == nil {
				t.Fatal("ambiguous or oversized capture JSON was accepted")
			}
		})
	}
}

func TestControllerEvidenceCaptureRequiresPurposeSeparatedWitnessAndClosedHeads(t *testing.T) {
	fixture := newControllerCaptureProtocolFixture(t)
	if _, err := SignControllerEvidenceCaptureV1(
		fixture.statement,
		fixture.frames,
		fixture.receiptPrivate,
	); err == nil {
		t.Fatal("receipt key was reused as the controller witness key")
	}

	for name, mutate := range map[string]func(*ControllerEvidenceCaptureStatementV1){
		"finding baseline": func(value *ControllerEvidenceCaptureStatementV1) {
			value.BaselineHead.Sequence = 0
		},
		"identity change": func(value *ControllerEvidenceCaptureStatementV1) {
			value.FinalHead.ReceiptEpoch++
		},
		"zero frames": func(value *ControllerEvidenceCaptureStatementV1) {
			value.FrameCount = 0
			value.FinalHead.Sequence = value.BaselineHead.Sequence
		},
		"sequence overflow": func(value *ControllerEvidenceCaptureStatementV1) {
			value.BaselineHead.Sequence = ^uint64(0)
			value.FinalHead.Sequence = 1
		},
		"time reversal": func(value *ControllerEvidenceCaptureStatementV1) {
			value.ObservedAt = "2026-06-30T23:59:59Z"
		},
		"observation after armed window": func(value *ControllerEvidenceCaptureStatementV1) {
			value.ObservedAt = "2026-07-01T01:00:00.000000001Z"
			value.SealedAt = value.ObservedAt
			value.ExportedAt = value.ObservedAt
		},
		"non-canonical time": func(value *ControllerEvidenceCaptureStatementV1) {
			value.SealedAt = "2026-07-01T02:00:00+02:00"
		},
		"command with slash": func(value *ControllerEvidenceCaptureStatementV1) {
			value.CanaryCommandID = "canary/command"
		},
		"command with space": func(value *ControllerEvidenceCaptureStatementV1) {
			value.CanaryCommandID = "canary command"
		},
		"command with control": func(value *ControllerEvidenceCaptureStatementV1) {
			value.CanaryCommandID = "canary\ncommand"
		},
	} {
		t.Run(name, func(t *testing.T) {
			statement := fixture.statement
			mutate(&statement)
			if err := statement.Validate(); err == nil {
				t.Fatal("invalid statement was accepted")
			}
		})
	}

	genesis := fixture.statement
	genesis.BaselineHead.Sequence = 0
	genesis.BaselineHead.ChainHash = captureProtocolDigest("0")
	genesis.FinalHead.Sequence = uint64(genesis.FrameCount)
	genesis.ActivationBeginSequence = 1
	if err := genesis.Validate(); err != nil {
		t.Fatalf("valid genesis baseline rejected: %v", err)
	}
}

func newControllerCaptureProtocolFixture(t *testing.T) controllerCaptureProtocolFixture {
	t.Helper()
	receiptPublic, receiptPrivate := captureProtocolKey(t)
	witnessPublic, witnessPrivate := captureProtocolKey(t)
	claim, err := NewExecutorEvidenceIdentityClaimV1(
		"controller-a",
		"enrollment-a",
		"node-a",
		"node-a",
		7,
		receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := SignExecutorEvidenceIdentityClaimV1(claim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{
		captureProtocolFrame("frame-one"),
		captureProtocolFrame("frame-two-longer"),
	}
	head := ExecutorEvidenceHeadV1{
		Stream:          ExecutorEvidenceStreamV1,
		ReceiptNodeID:   "node-a",
		ReceiptEpoch:    7,
		Sequence:        4,
		ChainHash:       captureProtocolDigest("1"),
		PublicKeySHA256: ExecutorEvidencePublicKeySHA256(receiptPublic),
	}
	final := head
	final.Sequence += uint64(len(frames))
	final.ChainHash = captureProtocolDigest("2")
	statement := ControllerEvidenceCaptureStatementV1{
		ProtocolVersion:            ControllerEvidenceCaptureProtocolV1,
		ControllerInstanceID:       "controller-a",
		CaptureID:                  "capture-a",
		NodeID:                     "node-a",
		TenantID:                   "tenant-a",
		RuntimeRef:                 "executor-" + strings.Repeat("a", 64),
		Generation:                 9,
		ActivationID:               "activation-a",
		CanaryCommandID:            "canary-command-a",
		ActivationBeginDigest:      captureProtocolDigest("6"),
		ActivationBeginSequence:    head.Sequence + 1,
		ActivationCheckpointDigest: captureProtocolDigest("3"),
		CapsuleDigest:              captureProtocolDigest("4"),
		PolicyDigest:               captureProtocolDigest("5"),
		IdentityProof:              proof,
		BaselineHead:               head,
		FinalHead:                  final,
		FrameCount:                 uint32(len(frames)),
		FramesDigest:               ControllerEvidenceCaptureFramesDigestV1(frames),
		ArmedAt:                    "2026-07-01T00:00:00Z",
		ObservedAt:                 "2026-07-01T00:01:00Z",
		SealedAt:                   "2026-07-01T00:02:00Z",
		ExportedAt:                 "2026-07-01T00:03:00Z",
	}
	capture, err := SignControllerEvidenceCaptureV1(statement, frames, witnessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return controllerCaptureProtocolFixture{
		frames: frames, statement: statement, capture: capture,
		receiptPublic: receiptPublic, receiptPrivate: receiptPrivate,
		witnessPublic: witnessPublic, witnessPrivate: witnessPrivate,
	}
}

func captureProtocolKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func captureProtocolFrame(payload string) []byte {
	frame := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	return append(frame, payload...)
}

func repeatedCaptureProtocolFrames(count, payloadBytes int) [][]byte {
	frames := make([][]byte, count)
	for index := range frames {
		frames[index] = captureProtocolFrame(strings.Repeat("x", payloadBytes))
	}
	return frames
}

func captureProtocolDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func cloneControllerCapture(value ControllerEvidenceCaptureV1) ControllerEvidenceCaptureV1 {
	clone := value
	clone.SignedFramesBase64 = append(
		ControllerEvidenceCaptureFrameEncodingsBase64V1(nil),
		value.SignedFramesBase64...,
	)
	return clone
}
