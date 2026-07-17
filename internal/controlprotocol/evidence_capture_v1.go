package controlprotocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	ControllerEvidenceCaptureProtocolV1 = 1

	MaxControllerEvidenceCaptureFrames            = 128
	MaxControllerEvidenceCaptureDecodedBytes      = 512 << 10
	MaxControllerEvidenceCaptureJSONBytes         = 1 << 20
	MaxControllerEvidenceCaptureObservationWindow = time.Hour

	ControllerEvidenceCapturePayloadTypeV1 = "application/vnd.steward.controller-evidence-capture.v1+binary"

	maxControllerEvidenceCaptureFrameBytes = (64 << 10) + 4
)

const (
	controllerEvidenceCaptureFramesDomainV1  = "steward-controller-evidence-capture-frames-v1\x00"
	controllerEvidenceCaptureWitnessDomainV1 = "steward-controller-evidence-capture-witness-v1\x00"
)

// ControllerEvidenceCaptureStatementV1 is the controller's complete assertion
// about one site-admin evidence capture. The frame count and digest bind the
// statement to exact native, length-prefixed Executor evidence frames.
type ControllerEvidenceCaptureStatementV1 struct {
	ProtocolVersion            int                             `json:"protocol_version"`
	ControllerInstanceID       string                          `json:"controller_instance_id"`
	CaptureID                  string                          `json:"capture_id"`
	NodeID                     string                          `json:"node_id"`
	TenantID                   string                          `json:"tenant_id"`
	RuntimeRef                 string                          `json:"runtime_ref"`
	Generation                 uint64                          `json:"generation"`
	ActivationID               string                          `json:"activation_id"`
	CanaryCommandID            string                          `json:"canary_command_id"`
	ActivationBeginDigest      string                          `json:"activation_begin_digest"`
	ActivationBeginSequence    uint64                          `json:"activation_begin_sequence"`
	ActivationCheckpointDigest string                          `json:"activation_checkpoint_digest"`
	CapsuleDigest              string                          `json:"capsule_digest"`
	PolicyDigest               string                          `json:"policy_digest"`
	IdentityProof              ExecutorEvidenceIdentityProofV1 `json:"identity_proof"`
	BaselineHead               ExecutorEvidenceHeadV1          `json:"baseline_head"`
	FinalHead                  ExecutorEvidenceHeadV1          `json:"final_head"`
	FrameCount                 uint32                          `json:"frame_count"`
	FramesDigest               string                          `json:"frames_digest"`
	ArmedAt                    string                          `json:"armed_at"`
	ObservedAt                 string                          `json:"observed_at"`
	SealedAt                   string                          `json:"sealed_at"`
	ExportedAt                 string                          `json:"exported_at"`
}

// ControllerEvidenceCaptureFrameEncodingsBase64V1 is deliberately a distinct
// wire type. A present JSON null is invalid; a capture always carries at least
// one exact native frame.
type ControllerEvidenceCaptureFrameEncodingsBase64V1 []string

func (frames *ControllerEvidenceCaptureFrameEncodingsBase64V1) UnmarshalJSON(raw []byte) error {
	if frames == nil {
		return errors.New("controller evidence capture frame collection is nil")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("controller evidence capture frame collection must be an array")
	}
	var decoded []string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*frames = decoded
	return nil
}

// ControllerEvidenceCaptureV1 carries the exact signed frames beside a
// dedicated controller-witness signature. The embedded witness public key is
// descriptive only; callers must verify against an independently pinned key.
type ControllerEvidenceCaptureV1 struct {
	PayloadType            string                                          `json:"payload_type"`
	Statement              ControllerEvidenceCaptureStatementV1            `json:"statement"`
	SignedFramesBase64     ControllerEvidenceCaptureFrameEncodingsBase64V1 `json:"signed_frames_base64"`
	WitnessPublicKeyBase64 string                                          `json:"witness_public_key_base64"`
	WitnessPublicKeySHA256 string                                          `json:"witness_public_key_sha256"`
	SignatureBase64        string                                          `json:"signature_base64"`
}

// Validate enforces the statement's closed identity, enrollment, chain, frame,
// and time relationships. It verifies the enrollment proof rather than merely
// accepting its self-declared public key.
func (statement ControllerEvidenceCaptureStatementV1) Validate() error {
	if statement.ProtocolVersion != ControllerEvidenceCaptureProtocolV1 ||
		!validEvidenceIdentity(statement.ControllerInstanceID, 128) ||
		!validEvidenceIdentity(statement.CaptureID, 128) ||
		!validEvidenceIdentity(statement.NodeID, 128) ||
		!validEvidenceIdentity(statement.TenantID, 128) ||
		!executorRuntimeRef(statement.RuntimeRef) ||
		statement.Generation == 0 ||
		!routeIdentifier(statement.ActivationID) ||
		!validEvidenceIdentity(statement.CanaryCommandID, 256) {
		return errors.New("controller evidence capture target identity is invalid")
	}
	if !ValidSHA256Digest(statement.ActivationBeginDigest) ||
		!ValidSHA256Digest(statement.ActivationCheckpointDigest) ||
		!ValidSHA256Digest(statement.CapsuleDigest) ||
		!ValidSHA256Digest(statement.PolicyDigest) ||
		!ValidSHA256Digest(statement.FramesDigest) {
		return errors.New("controller evidence capture digest is invalid")
	}
	if statement.FrameCount == 0 || statement.FrameCount > MaxControllerEvidenceCaptureFrames {
		return errors.New("controller evidence capture frame count is invalid")
	}
	if err := statement.IdentityProof.Validate(); err != nil {
		return fmt.Errorf("controller evidence capture enrollment proof: %w", err)
	}
	claim := statement.IdentityProof.Claim
	if claim.ControllerInstanceID != statement.ControllerInstanceID ||
		claim.ControlNodeID != statement.NodeID {
		return errors.New("controller evidence capture does not match its enrolled controller and node")
	}
	if err := statement.BaselineHead.Validate(); err != nil {
		return fmt.Errorf("controller evidence capture baseline head: %w", err)
	}
	if err := statement.FinalHead.Validate(); err != nil {
		return fmt.Errorf("controller evidence capture final head: %w", err)
	}
	if !sameExecutorEvidenceIdentity(statement.BaselineHead, statement.FinalHead) ||
		statement.FinalHead.Stream != claim.Stream ||
		statement.FinalHead.ReceiptNodeID != claim.ReceiptNodeID ||
		statement.FinalHead.ReceiptEpoch != claim.ReceiptEpoch ||
		statement.FinalHead.PublicKeySHA256 != claim.PublicKeySHA256 {
		return errors.New("controller evidence capture heads changed the enrolled receipt identity")
	}
	if statement.BaselineHead.Sequence > ^uint64(0)-uint64(statement.FrameCount) ||
		statement.FinalHead.Sequence != statement.BaselineHead.Sequence+uint64(statement.FrameCount) {
		return errors.New("controller evidence capture heads do not match the exact frame count")
	}
	if statement.ActivationBeginSequence <= statement.BaselineHead.Sequence ||
		statement.ActivationBeginSequence >= statement.FinalHead.Sequence {
		return errors.New("controller evidence capture activation begin is outside the checkpoint range")
	}
	times := []string{
		statement.ArmedAt,
		statement.ObservedAt,
		statement.SealedAt,
		statement.ExportedAt,
	}
	var previous time.Time
	for index, value := range times {
		if !validCanonicalEvidenceTime(value) {
			return errors.New("controller evidence capture timestamp is invalid")
		}
		parsed, _ := time.Parse(time.RFC3339Nano, value)
		if index > 0 && parsed.Before(previous) {
			return errors.New("controller evidence capture timestamps are out of order")
		}
		previous = parsed
	}
	armed, _ := time.Parse(time.RFC3339Nano, statement.ArmedAt)
	observed, _ := time.Parse(time.RFC3339Nano, statement.ObservedAt)
	if observed.Sub(armed) > MaxControllerEvidenceCaptureObservationWindow {
		return errors.New("controller evidence capture observation exceeds its armed window")
	}
	return nil
}

// ControllerEvidenceCaptureSigningStatementV1 returns the exact
// purpose-separated bytes signed by the controller witness key.
func ControllerEvidenceCaptureSigningStatementV1(statement ControllerEvidenceCaptureStatementV1) ([]byte, error) {
	if err := statement.Validate(); err != nil {
		return nil, err
	}
	identityStatement, _ := ExecutorEvidenceIdentityProofStatementV1(statement.IdentityProof.Claim)
	out := append([]byte(nil), controllerEvidenceCaptureWitnessDomainV1...)
	out = appendEvidenceText(out, ControllerEvidenceCapturePayloadTypeV1)
	out = appendEvidenceUint64(out, uint64(statement.ProtocolVersion))
	out = appendEvidenceText(out, statement.ControllerInstanceID)
	out = appendEvidenceText(out, statement.CaptureID)
	out = appendEvidenceText(out, statement.NodeID)
	out = appendEvidenceText(out, statement.TenantID)
	out = appendEvidenceText(out, statement.RuntimeRef)
	out = appendEvidenceUint64(out, statement.Generation)
	out = appendEvidenceText(out, statement.ActivationID)
	out = appendEvidenceText(out, statement.CanaryCommandID)
	out = appendEvidenceText(out, statement.ActivationBeginDigest)
	out = appendEvidenceUint64(out, statement.ActivationBeginSequence)
	out = appendEvidenceText(out, statement.ActivationCheckpointDigest)
	out = appendEvidenceText(out, statement.CapsuleDigest)
	out = appendEvidenceText(out, statement.PolicyDigest)
	out = appendEvidenceBytes(out, identityStatement)
	out = appendEvidenceText(out, statement.IdentityProof.SignatureBase64)
	out = appendEvidenceHead(out, statement.BaselineHead)
	out = appendEvidenceHead(out, statement.FinalHead)
	out = appendEvidenceUint64(out, uint64(statement.FrameCount))
	out = appendEvidenceText(out, statement.FramesDigest)
	out = appendEvidenceText(out, statement.ArmedAt)
	out = appendEvidenceText(out, statement.ObservedAt)
	out = appendEvidenceText(out, statement.SealedAt)
	out = appendEvidenceText(out, statement.ExportedAt)
	return out, nil
}

// SignControllerEvidenceCaptureV1 signs one already-bound statement and exact
// frame collection. It refuses to reuse the enrolled receipt key as the
// controller witness authority.
func SignControllerEvidenceCaptureV1(
	statement ControllerEvidenceCaptureStatementV1,
	frames [][]byte,
	private ed25519.PrivateKey,
) (ControllerEvidenceCaptureV1, error) {
	if len(private) != ed25519.PrivateKeySize {
		return ControllerEvidenceCaptureV1{}, errors.New("controller evidence capture witness private key has invalid length")
	}
	if err := validateControllerEvidenceCaptureFrames(frames); err != nil {
		return ControllerEvidenceCaptureV1{}, err
	}
	if uint32(len(frames)) != statement.FrameCount ||
		ControllerEvidenceCaptureFramesDigestV1(frames) != statement.FramesDigest {
		return ControllerEvidenceCaptureV1{}, errors.New("controller evidence capture frames do not match the statement")
	}
	if err := statement.Validate(); err != nil {
		return ControllerEvidenceCaptureV1{}, err
	}
	public := private.Public().(ed25519.PublicKey)
	if ExecutorEvidencePublicKeySHA256(public) == statement.IdentityProof.Claim.PublicKeySHA256 {
		return ControllerEvidenceCaptureV1{}, errors.New("controller evidence capture witness key must be distinct from the receipt key")
	}
	signingStatement, err := ControllerEvidenceCaptureSigningStatementV1(statement)
	if err != nil {
		return ControllerEvidenceCaptureV1{}, err
	}
	encodedFrames := make(ControllerEvidenceCaptureFrameEncodingsBase64V1, len(frames))
	for index, frame := range frames {
		encodedFrames[index] = base64.StdEncoding.EncodeToString(frame)
	}
	export := ControllerEvidenceCaptureV1{
		PayloadType:            ControllerEvidenceCapturePayloadTypeV1,
		Statement:              statement,
		SignedFramesBase64:     encodedFrames,
		WitnessPublicKeyBase64: base64.StdEncoding.EncodeToString(public),
		WitnessPublicKeySHA256: ExecutorEvidencePublicKeySHA256(public),
		SignatureBase64:        base64.StdEncoding.EncodeToString(ed25519.Sign(private, signingStatement)),
	}
	if err := export.Validate(); err != nil {
		return ControllerEvidenceCaptureV1{}, err
	}
	return export, nil
}

// Validate verifies the embedded witness signature and exact frame binding.
// This establishes internal authenticity, not trust in the embedded key.
func (capture ControllerEvidenceCaptureV1) Validate() error {
	if capture.PayloadType != ControllerEvidenceCapturePayloadTypeV1 {
		return errors.New("controller evidence capture payload type is invalid")
	}
	if err := capture.Statement.Validate(); err != nil {
		return err
	}
	frames, err := capture.DecodeFrames()
	if err != nil {
		return err
	}
	if uint32(len(frames)) != capture.Statement.FrameCount ||
		ControllerEvidenceCaptureFramesDigestV1(frames) != capture.Statement.FramesDigest {
		return errors.New("controller evidence capture frames do not match the signed binding")
	}
	public, err := executorEvidencePublicKey(
		capture.WitnessPublicKeyBase64,
		capture.WitnessPublicKeySHA256,
	)
	if err != nil {
		return err
	}
	if capture.WitnessPublicKeySHA256 == capture.Statement.IdentityProof.Claim.PublicKeySHA256 {
		return errors.New("controller evidence capture witness key is not purpose-separated from the receipt key")
	}
	signature, err := canonicalEvidenceSignature(capture.SignatureBase64)
	if err != nil {
		return err
	}
	signingStatement, err := ControllerEvidenceCaptureSigningStatementV1(capture.Statement)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, signingStatement, signature) {
		return errors.New("controller evidence capture signature is invalid")
	}
	raw, err := json.Marshal(capture)
	if err != nil {
		return fmt.Errorf("encode controller evidence capture: %w", err)
	}
	if len(raw) > MaxControllerEvidenceCaptureJSONBytes {
		return fmt.Errorf(
			"controller evidence capture contains %d JSON bytes, limit is %d",
			len(raw),
			MaxControllerEvidenceCaptureJSONBytes,
		)
	}
	return nil
}

// DecodeFrames returns independent copies of the exact native signed frames.
func (capture ControllerEvidenceCaptureV1) DecodeFrames() ([][]byte, error) {
	return decodeControllerEvidenceCaptureFrames(capture.SignedFramesBase64)
}

// VerifyControllerEvidenceCaptureV1 requires the caller's out-of-band witness
// key to match the embedded key after validating the complete capture.
func VerifyControllerEvidenceCaptureV1(
	capture ControllerEvidenceCaptureV1,
	trusted ed25519.PublicKey,
) error {
	if len(trusted) != ed25519.PublicKeySize {
		return errors.New("trusted controller evidence capture witness key has invalid length")
	}
	if err := capture.Validate(); err != nil {
		return err
	}
	public, _ := executorEvidencePublicKey(
		capture.WitnessPublicKeyBase64,
		capture.WitnessPublicKeySHA256,
	)
	if !bytes.Equal(public, trusted) {
		return errors.New("controller evidence capture was not signed by the trusted witness key")
	}
	return nil
}

// DecodeControllerEvidenceCaptureV1 applies strict, bounded JSON decoding
// before validating signatures and frame bindings.
func DecodeControllerEvidenceCaptureV1(raw []byte) (ControllerEvidenceCaptureV1, error) {
	var capture ControllerEvidenceCaptureV1
	if err := dsse.DecodeStrictInto(raw, MaxControllerEvidenceCaptureJSONBytes, &capture); err != nil {
		return ControllerEvidenceCaptureV1{}, err
	}
	if err := capture.Validate(); err != nil {
		return ControllerEvidenceCaptureV1{}, err
	}
	return capture, nil
}

// ControllerEvidenceCaptureFramesDigestV1 returns the capture-specific,
// domain-separated digest of exact decoded native frame bytes.
func ControllerEvidenceCaptureFramesDigestV1(frames [][]byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(controllerEvidenceCaptureFramesDomainV1))
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(len(frames)))
	_, _ = hash.Write(encoded[:])
	for _, frame := range frames {
		binary.BigEndian.PutUint32(encoded[:], uint32(len(frame)))
		_, _ = hash.Write(encoded[:])
		_, _ = hash.Write(frame)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func validateControllerEvidenceCaptureFrames(frames [][]byte) error {
	if len(frames) == 0 || len(frames) > MaxControllerEvidenceCaptureFrames {
		return fmt.Errorf(
			"controller evidence capture must contain 1 through %d frames",
			MaxControllerEvidenceCaptureFrames,
		)
	}
	total := 0
	for index, frame := range frames {
		if len(frame) < 5 || len(frame) > maxControllerEvidenceCaptureFrameBytes ||
			int(binary.BigEndian.Uint32(frame[:4])) != len(frame)-4 {
			return fmt.Errorf("controller evidence capture frame %d is not one native length-prefixed frame", index+1)
		}
		if total > MaxControllerEvidenceCaptureDecodedBytes-len(frame) {
			return fmt.Errorf(
				"controller evidence capture exceeds %d decoded bytes",
				MaxControllerEvidenceCaptureDecodedBytes,
			)
		}
		total += len(frame)
	}
	return nil
}

func decodeControllerEvidenceCaptureFrames(
	encoded ControllerEvidenceCaptureFrameEncodingsBase64V1,
) ([][]byte, error) {
	if len(encoded) == 0 || len(encoded) > MaxControllerEvidenceCaptureFrames {
		return nil, fmt.Errorf(
			"controller evidence capture must contain 1 through %d encoded frames",
			MaxControllerEvidenceCaptureFrames,
		)
	}
	frames := make([][]byte, 0, len(encoded))
	total := 0
	for index, value := range encoded {
		if value == "" || len(value) > base64.StdEncoding.EncodedLen(maxControllerEvidenceCaptureFrameBytes) ||
			strings.ContainsAny(value, "\r\n \t") {
			return nil, fmt.Errorf("controller evidence capture frame %d encoding is invalid", index+1)
		}
		frame, err := base64.StdEncoding.DecodeString(value)
		if err != nil || base64.StdEncoding.EncodeToString(frame) != value {
			return nil, fmt.Errorf("controller evidence capture frame %d is not canonical base64", index+1)
		}
		if total > MaxControllerEvidenceCaptureDecodedBytes-len(frame) {
			return nil, fmt.Errorf(
				"controller evidence capture exceeds %d decoded bytes",
				MaxControllerEvidenceCaptureDecodedBytes,
			)
		}
		total += len(frame)
		frames = append(frames, frame)
	}
	if err := validateControllerEvidenceCaptureFrames(frames); err != nil {
		return nil, err
	}
	return frames, nil
}
