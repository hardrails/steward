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
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	ExecutorEvidenceProtocolV1 = 1
	ExecutorEvidenceStreamV1   = "executor"

	MaxExecutorEvidenceFrames       = 128
	MaxExecutorEvidenceDecodedBytes = 700 << 10
	MaxExecutorEvidenceJSONBytes    = 1 << 20
	MaxExecutorEvidenceFrameBytes   = (64 << 10) + 4
	MaxExecutorEvidenceChallenge    = 256

	ExecutorEvidenceStatusUnwitnessed          = "unwitnessed"
	ExecutorEvidenceStatusCurrent              = "current"
	ExecutorEvidenceStatusRollbackDetected     = "rollback_detected"
	ExecutorEvidenceStatusEquivocationDetected = "equivocation_detected"

	ExecutorEvidenceFindingRollback     = "rollback"
	ExecutorEvidenceFindingEquivocation = "equivocation"

	ExecutorEvidenceExportPayloadTypeV1 = "application/vnd.steward.executor-evidence-witness.v1+binary"
)

const (
	executorEvidenceEnrollmentProofPayloadTypeV1 = "application/vnd.steward.executor-evidence-enrollment-proof.v1+binary"
	executorEvidenceHeadProofPayloadTypeV1       = "application/vnd.steward.executor-evidence-head-proof.v1+binary"
	executorEvidenceEnrollmentProofDomainV1      = "steward-executor-evidence-enrollment-proof-v1\x00"
	executorEvidenceHeadProofDomainV1            = "steward-executor-evidence-head-proof-v1\x00"
	executorEvidenceFramesDigestDomainV1         = "steward-executor-evidence-frames-v1\x00"
	executorEvidenceExportDomainV1               = "steward-executor-evidence-witness-export-v1\x00"
)

// ExecutorEvidenceIdentityClaimV1 is the complete receipt-key identity pinned
// during one enrollment exchange. The enrollment proof binds this exact claim
// to the receipt private key before the controller accepts the public half.
type ExecutorEvidenceIdentityClaimV1 struct {
	ProtocolVersion      int    `json:"protocol_version"`
	ControllerInstanceID string `json:"controller_instance_id"`
	EnrollmentID         string `json:"enrollment_id"`
	ControlNodeID        string `json:"control_node_id"`
	Stream               string `json:"stream"`
	ReceiptNodeID        string `json:"receipt_node_id"`
	ReceiptEpoch         uint64 `json:"receipt_epoch"`
	PublicKeyBase64      string `json:"public_key_base64"`
	PublicKeySHA256      string `json:"public_key_sha256"`
}

// ExecutorEvidenceIdentityProofV1 proves possession of the receipt private key
// while binding it to one controller, enrollment, control node, receipt node,
// stream, and epoch. A proof cannot be replayed into another enrollment.
type ExecutorEvidenceIdentityProofV1 struct {
	Claim           ExecutorEvidenceIdentityClaimV1 `json:"claim"`
	SignatureBase64 string                          `json:"signature_base64"`
}

// ExecutorEvidenceHeadV1 is a controller-derived checkpoint. Sequence zero
// represents the empty chain and must use the all-zero chain hash.
type ExecutorEvidenceHeadV1 struct {
	Stream          string `json:"stream"`
	ReceiptNodeID   string `json:"receipt_node_id"`
	ReceiptEpoch    uint64 `json:"receipt_epoch"`
	Sequence        uint64 `json:"sequence"`
	ChainHash       string `json:"chain_hash"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

// ExecutorEvidenceHeadClaimV1 is a receipt-key-signed response to a fresh
// controller challenge. It binds the polled controller checkpoint, the
// reported local head, and the exact decoded frames submitted with the report.
// An empty report may prove equality or a conflicting local coordinate, but it
// cannot be transformed into an advancement by adding frames after signing.
type ExecutorEvidenceHeadClaimV1 struct {
	ProtocolVersion      int    `json:"protocol_version"`
	ControllerInstanceID string `json:"controller_instance_id"`
	ControlNodeID        string `json:"control_node_id"`
	Stream               string `json:"stream"`
	ReceiptNodeID        string `json:"receipt_node_id"`
	ReceiptEpoch         uint64 `json:"receipt_epoch"`
	BaseSequence         uint64 `json:"base_sequence"`
	BaseChainHash        string `json:"base_chain_hash"`
	Sequence             uint64 `json:"sequence"`
	ChainHash            string `json:"chain_hash"`
	FrameCount           uint32 `json:"frame_count"`
	FramesDigest         string `json:"frames_digest"`
	PublicKeySHA256      string `json:"public_key_sha256"`
	Challenge            string `json:"challenge"`
}

type ExecutorEvidenceHeadProofV1 struct {
	Claim           ExecutorEvidenceHeadClaimV1 `json:"claim"`
	SignatureBase64 string                      `json:"signature_base64"`
}

type ExecutorEvidencePollRequestV1 struct {
	ProtocolVersion      int    `json:"protocol_version"`
	ControllerInstanceID string `json:"controller_instance_id"`
	ControlNodeID        string `json:"control_node_id"`
	Stream               string `json:"stream"`
	ReceiptNodeID        string `json:"receipt_node_id"`
	ReceiptEpoch         uint64 `json:"receipt_epoch"`
	PublicKeySHA256      string `json:"public_key_sha256"`
}

type ExecutorEvidencePollResponseV1 struct {
	ProtocolVersion int                      `json:"protocol_version"`
	Challenge       string                   `json:"challenge"`
	Status          ExecutorEvidenceStatusV1 `json:"status"`
}

// ExecutorEvidenceReportV1 always carries a challenge-bound signed reported
// head. With frames, that head must equal the final submitted frame. An empty
// list can refresh or expose equality, rollback, or a fork by signing the true
// local head, but it must never advance a controller checkpoint.
type ExecutorEvidenceReportV1 struct {
	ProtocolVersion    int                                    `json:"protocol_version"`
	HeadProof          ExecutorEvidenceHeadProofV1            `json:"head_proof"`
	SignedFramesBase64 ExecutorEvidenceFrameEncodingsBase64V1 `json:"signed_frames_base64,omitempty"`
}

// ExecutorEvidenceFrameEncodingsBase64V1 is an optional array when omitted,
// but an explicit JSON null is invalid. This preserves one unambiguous JSON
// type for a present frame collection.
type ExecutorEvidenceFrameEncodingsBase64V1 []string

func (frames *ExecutorEvidenceFrameEncodingsBase64V1) UnmarshalJSON(raw []byte) error {
	if frames == nil {
		return errors.New("executor evidence frame collection is nil")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("executor evidence frame collection must be an array")
	}
	var decoded []string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*frames = decoded
	return nil
}

type ExecutorEvidenceReportResponseV1 struct {
	ProtocolVersion int                      `json:"protocol_version"`
	Applied         bool                     `json:"applied"`
	Status          ExecutorEvidenceStatusV1 `json:"status"`
}

// ExecutorEvidenceFindingV1 retains the signed head that conflicted with one
// controller checkpoint. ComparedHead is that exact historical checkpoint;
// Status.Head may be a later last-good checkpoint retained before the finding
// was durably recorded.
type ExecutorEvidenceFindingV1 struct {
	Kind         string                 `json:"kind"`
	DetectedAt   string                 `json:"detected_at"`
	ComparedHead ExecutorEvidenceHeadV1 `json:"compared_head"`
	ObservedHead ExecutorEvidenceHeadV1 `json:"observed_head"`
}

type ExecutorEvidenceStatusV1 struct {
	State       string                     `json:"state"`
	Head        *ExecutorEvidenceHeadV1    `json:"head,omitempty"`
	WitnessedAt string                     `json:"witnessed_at,omitempty"`
	Finding     *ExecutorEvidenceFindingV1 `json:"finding,omitempty"`
}

// ExecutorEvidenceInspectionV1 is the bounded online view of one controller
// witness. IdentityProof is absent only for a legacy, unwitnessed node.
type ExecutorEvidenceInspectionV1 struct {
	ProtocolVersion      int                              `json:"protocol_version"`
	ControllerInstanceID string                           `json:"controller_instance_id"`
	ControlNodeID        string                           `json:"control_node_id"`
	IdentityProof        *ExecutorEvidenceIdentityProofV1 `json:"identity_proof,omitempty"`
	Status               ExecutorEvidenceStatusV1         `json:"status"`
}

// ExecutorEvidenceExportStatementV1 is the non-secret controller assertion
// carried by an offline witness export. IdentityProof lets an auditor verify
// that the enrolled node possessed the pinned receipt key.
type ExecutorEvidenceExportStatementV1 struct {
	ProtocolVersion      int                             `json:"protocol_version"`
	ControllerInstanceID string                          `json:"controller_instance_id"`
	ControlNodeID        string                          `json:"control_node_id"`
	IdentityProof        ExecutorEvidenceIdentityProofV1 `json:"identity_proof"`
	Status               ExecutorEvidenceStatusV1        `json:"status"`
	ExportedAt           string                          `json:"exported_at"`
}

// ExecutorEvidenceExportV1 is signed by a dedicated controller witness key.
// Callers must pin that key out of band; the embedded public key makes an
// export self-describing, not self-authorizing.
type ExecutorEvidenceExportV1 struct {
	PayloadType            string                            `json:"payload_type"`
	Statement              ExecutorEvidenceExportStatementV1 `json:"statement"`
	WitnessPublicKeyBase64 string                            `json:"witness_public_key_base64"`
	WitnessPublicKeySHA256 string                            `json:"witness_public_key_sha256"`
	SignatureBase64        string                            `json:"signature_base64"`
}

func NewExecutorEvidenceIdentityClaimV1(controllerInstanceID, enrollmentID, controlNodeID, receiptNodeID string, receiptEpoch uint64, public ed25519.PublicKey) (ExecutorEvidenceIdentityClaimV1, error) {
	if len(public) != ed25519.PublicKeySize {
		return ExecutorEvidenceIdentityClaimV1{}, errors.New("executor evidence public key has invalid length")
	}
	claim := ExecutorEvidenceIdentityClaimV1{
		ProtocolVersion: ExecutorEvidenceProtocolV1, ControllerInstanceID: controllerInstanceID,
		EnrollmentID: enrollmentID, ControlNodeID: controlNodeID, Stream: ExecutorEvidenceStreamV1,
		ReceiptNodeID: receiptNodeID, ReceiptEpoch: receiptEpoch,
		PublicKeyBase64: base64.StdEncoding.EncodeToString(public), PublicKeySHA256: ExecutorEvidencePublicKeySHA256(public),
	}
	if err := claim.Validate(); err != nil {
		return ExecutorEvidenceIdentityClaimV1{}, err
	}
	return claim, nil
}

func (claim ExecutorEvidenceIdentityClaimV1) Validate() error {
	if claim.ProtocolVersion != ExecutorEvidenceProtocolV1 ||
		!validEvidenceIdentity(claim.ControllerInstanceID, 128) ||
		!validEvidenceIdentity(claim.EnrollmentID, 128) ||
		!validEvidenceIdentity(claim.ControlNodeID, 128) ||
		claim.Stream != ExecutorEvidenceStreamV1 ||
		!validEvidenceReceiptNodeID(claim.ReceiptNodeID) ||
		claim.ReceiptEpoch == 0 {
		return errors.New("executor evidence enrollment identity is invalid")
	}
	if _, err := executorEvidencePublicKey(claim.PublicKeyBase64, claim.PublicKeySHA256); err != nil {
		return err
	}
	return nil
}

// ExecutorEvidenceIdentityProofStatementV1 returns the exact
// domain-separated bytes signed by an enrollment proof.
func ExecutorEvidenceIdentityProofStatementV1(claim ExecutorEvidenceIdentityClaimV1) ([]byte, error) {
	if err := claim.Validate(); err != nil {
		return nil, err
	}
	statement := append([]byte(nil), executorEvidenceEnrollmentProofDomainV1...)
	statement = appendEvidenceText(statement, executorEvidenceEnrollmentProofPayloadTypeV1)
	statement = appendEvidenceUint64(statement, uint64(claim.ProtocolVersion))
	statement = appendEvidenceText(statement, claim.ControllerInstanceID)
	statement = appendEvidenceText(statement, claim.EnrollmentID)
	statement = appendEvidenceText(statement, claim.ControlNodeID)
	statement = appendEvidenceText(statement, claim.Stream)
	statement = appendEvidenceText(statement, claim.ReceiptNodeID)
	statement = appendEvidenceUint64(statement, claim.ReceiptEpoch)
	statement = appendEvidenceText(statement, claim.PublicKeyBase64)
	statement = appendEvidenceText(statement, claim.PublicKeySHA256)
	return statement, nil
}

func SignExecutorEvidenceIdentityClaimV1(claim ExecutorEvidenceIdentityClaimV1, private ed25519.PrivateKey) (ExecutorEvidenceIdentityProofV1, error) {
	if len(private) != ed25519.PrivateKeySize {
		return ExecutorEvidenceIdentityProofV1{}, errors.New("executor evidence private key has invalid length")
	}
	public, err := executorEvidencePublicKey(claim.PublicKeyBase64, claim.PublicKeySHA256)
	if err != nil || !bytes.Equal(public, private.Public().(ed25519.PublicKey)) {
		return ExecutorEvidenceIdentityProofV1{}, errors.New("executor evidence private key does not match the enrollment claim")
	}
	statement, err := ExecutorEvidenceIdentityProofStatementV1(claim)
	if err != nil {
		return ExecutorEvidenceIdentityProofV1{}, err
	}
	return ExecutorEvidenceIdentityProofV1{
		Claim: claim, SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(private, statement)),
	}, nil
}

func (proof ExecutorEvidenceIdentityProofV1) Validate() error {
	public, err := executorEvidencePublicKey(proof.Claim.PublicKeyBase64, proof.Claim.PublicKeySHA256)
	if err != nil {
		return err
	}
	signature, err := canonicalEvidenceSignature(proof.SignatureBase64)
	if err != nil {
		return err
	}
	statement, err := ExecutorEvidenceIdentityProofStatementV1(proof.Claim)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, statement, signature) {
		return errors.New("executor evidence enrollment proof signature is invalid")
	}
	return nil
}

// VerifyExecutorEvidenceIdentityProofV1 verifies proof of possession and
// returns an independent copy of the public key that the controller may pin.
func VerifyExecutorEvidenceIdentityProofV1(proof ExecutorEvidenceIdentityProofV1) (ed25519.PublicKey, error) {
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	public, _ := executorEvidencePublicKey(proof.Claim.PublicKeyBase64, proof.Claim.PublicKeySHA256)
	return public, nil
}

func (head ExecutorEvidenceHeadV1) Validate() error {
	if head.Stream != ExecutorEvidenceStreamV1 || !validEvidenceReceiptNodeID(head.ReceiptNodeID) ||
		head.ReceiptEpoch == 0 || !ValidSHA256Digest(head.ChainHash) || !ValidSHA256Digest(head.PublicKeySHA256) {
		return errors.New("executor evidence head is invalid")
	}
	if head.Sequence == 0 && head.ChainHash != zeroExecutorEvidenceChainHash() {
		return errors.New("empty executor evidence head must use the zero chain hash")
	}
	if head.Sequence > 0 && head.ChainHash == zeroExecutorEvidenceChainHash() {
		return errors.New("non-empty executor evidence head cannot use the zero chain hash")
	}
	return nil
}

func NewExecutorEvidenceHeadClaimV1(
	controllerInstanceID, controlNodeID string,
	base, reported ExecutorEvidenceHeadV1,
	challenge string,
	frames [][]byte,
	public ed25519.PublicKey,
) (ExecutorEvidenceHeadClaimV1, error) {
	if len(public) != ed25519.PublicKeySize {
		return ExecutorEvidenceHeadClaimV1{}, errors.New("executor evidence public key has invalid length")
	}
	if err := validateExecutorEvidenceDecodedFrames(frames); err != nil {
		return ExecutorEvidenceHeadClaimV1{}, err
	}
	if err := base.Validate(); err != nil {
		return ExecutorEvidenceHeadClaimV1{}, fmt.Errorf("executor evidence base head is invalid: %w", err)
	}
	if err := reported.Validate(); err != nil {
		return ExecutorEvidenceHeadClaimV1{}, fmt.Errorf("executor evidence reported head is invalid: %w", err)
	}
	if !sameExecutorEvidenceIdentity(base, reported) {
		return ExecutorEvidenceHeadClaimV1{}, errors.New("executor evidence base and reported heads use different receipt identities")
	}
	publicKeySHA256 := ExecutorEvidencePublicKeySHA256(public)
	if reported.PublicKeySHA256 != publicKeySHA256 {
		return ExecutorEvidenceHeadClaimV1{}, errors.New("executor evidence heads do not match the supplied public key")
	}
	claim := ExecutorEvidenceHeadClaimV1{
		ProtocolVersion: ExecutorEvidenceProtocolV1, ControllerInstanceID: controllerInstanceID,
		ControlNodeID: controlNodeID, Stream: reported.Stream, ReceiptNodeID: reported.ReceiptNodeID,
		ReceiptEpoch: reported.ReceiptEpoch, BaseSequence: base.Sequence, BaseChainHash: base.ChainHash,
		Sequence: reported.Sequence, ChainHash: reported.ChainHash,
		FrameCount: uint32(len(frames)), FramesDigest: ExecutorEvidenceFramesDigestV1(frames),
		PublicKeySHA256: publicKeySHA256, Challenge: challenge,
	}
	if err := claim.Validate(); err != nil {
		return ExecutorEvidenceHeadClaimV1{}, err
	}
	return claim, nil
}

func (claim ExecutorEvidenceHeadClaimV1) Base() ExecutorEvidenceHeadV1 {
	return ExecutorEvidenceHeadV1{
		Stream: claim.Stream, ReceiptNodeID: claim.ReceiptNodeID, ReceiptEpoch: claim.ReceiptEpoch,
		Sequence: claim.BaseSequence, ChainHash: claim.BaseChainHash, PublicKeySHA256: claim.PublicKeySHA256,
	}
}

func (claim ExecutorEvidenceHeadClaimV1) Head() ExecutorEvidenceHeadV1 {
	return ExecutorEvidenceHeadV1{
		Stream: claim.Stream, ReceiptNodeID: claim.ReceiptNodeID, ReceiptEpoch: claim.ReceiptEpoch,
		Sequence: claim.Sequence, ChainHash: claim.ChainHash, PublicKeySHA256: claim.PublicKeySHA256,
	}
}

func (claim ExecutorEvidenceHeadClaimV1) Validate() error {
	if claim.ProtocolVersion != ExecutorEvidenceProtocolV1 ||
		!validEvidenceIdentity(claim.ControllerInstanceID, 128) ||
		!validEvidenceIdentity(claim.ControlNodeID, 128) ||
		!validEvidenceChallenge(claim.Challenge) {
		return errors.New("executor evidence head proof identity or challenge is invalid")
	}
	if err := claim.Base().Validate(); err != nil {
		return err
	}
	if err := claim.Head().Validate(); err != nil {
		return err
	}
	if claim.FrameCount > MaxExecutorEvidenceFrames || !ValidSHA256Digest(claim.FramesDigest) {
		return errors.New("executor evidence head proof frame binding is invalid")
	}
	if claim.FrameCount == 0 && claim.FramesDigest != ExecutorEvidenceFramesDigestV1(nil) {
		return errors.New("empty executor evidence head proof has a non-empty frame digest")
	}
	if claim.FrameCount > 0 {
		if claim.BaseSequence > ^uint64(0)-uint64(claim.FrameCount) ||
			claim.Sequence != claim.BaseSequence+uint64(claim.FrameCount) {
			return errors.New("executor evidence advancing head does not match its frame count")
		}
	}
	return nil
}

// ExecutorEvidenceHeadProofStatementV1 returns the exact challenge-bound bytes
// signed by the receipt key.
func ExecutorEvidenceHeadProofStatementV1(claim ExecutorEvidenceHeadClaimV1) ([]byte, error) {
	if err := claim.Validate(); err != nil {
		return nil, err
	}
	statement := append([]byte(nil), executorEvidenceHeadProofDomainV1...)
	statement = appendEvidenceText(statement, executorEvidenceHeadProofPayloadTypeV1)
	statement = appendEvidenceUint64(statement, uint64(claim.ProtocolVersion))
	statement = appendEvidenceText(statement, claim.ControllerInstanceID)
	statement = appendEvidenceText(statement, claim.ControlNodeID)
	statement = appendEvidenceText(statement, claim.Stream)
	statement = appendEvidenceText(statement, claim.ReceiptNodeID)
	statement = appendEvidenceUint64(statement, claim.ReceiptEpoch)
	statement = appendEvidenceUint64(statement, claim.BaseSequence)
	statement = appendEvidenceText(statement, claim.BaseChainHash)
	statement = appendEvidenceUint64(statement, claim.Sequence)
	statement = appendEvidenceText(statement, claim.ChainHash)
	statement = appendEvidenceUint64(statement, uint64(claim.FrameCount))
	statement = appendEvidenceText(statement, claim.FramesDigest)
	statement = appendEvidenceText(statement, claim.PublicKeySHA256)
	statement = appendEvidenceText(statement, claim.Challenge)
	return statement, nil
}

func SignExecutorEvidenceHeadClaimV1(claim ExecutorEvidenceHeadClaimV1, private ed25519.PrivateKey) (ExecutorEvidenceHeadProofV1, error) {
	if len(private) != ed25519.PrivateKeySize ||
		claim.PublicKeySHA256 != ExecutorEvidencePublicKeySHA256(private.Public().(ed25519.PublicKey)) {
		return ExecutorEvidenceHeadProofV1{}, errors.New("executor evidence private key does not match the head claim")
	}
	statement, err := ExecutorEvidenceHeadProofStatementV1(claim)
	if err != nil {
		return ExecutorEvidenceHeadProofV1{}, err
	}
	return ExecutorEvidenceHeadProofV1{
		Claim: claim, SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(private, statement)),
	}, nil
}

func (proof ExecutorEvidenceHeadProofV1) Validate() error {
	if err := proof.Claim.Validate(); err != nil {
		return err
	}
	_, err := canonicalEvidenceSignature(proof.SignatureBase64)
	return err
}

// VerifyExecutorEvidenceHeadProofV1 establishes authenticity against the
// controller-pinned key. HeadProof.Validate checks only the closed shape and
// canonical signature encoding because the proof deliberately does not carry a
// self-authorizing public key.
func VerifyExecutorEvidenceHeadProofV1(proof ExecutorEvidenceHeadProofV1, public ed25519.PublicKey) error {
	if len(public) != ed25519.PublicKeySize ||
		proof.Claim.PublicKeySHA256 != ExecutorEvidencePublicKeySHA256(public) {
		return errors.New("executor evidence head proof key is invalid")
	}
	signature, err := canonicalEvidenceSignature(proof.SignatureBase64)
	if err != nil {
		return err
	}
	statement, err := ExecutorEvidenceHeadProofStatementV1(proof.Claim)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, statement, signature) {
		return errors.New("executor evidence head proof signature is invalid")
	}
	return nil
}

func (request ExecutorEvidencePollRequestV1) Validate() error {
	if request.ProtocolVersion != ExecutorEvidenceProtocolV1 ||
		!validEvidenceIdentity(request.ControllerInstanceID, 128) ||
		!validEvidenceIdentity(request.ControlNodeID, 128) ||
		request.Stream != ExecutorEvidenceStreamV1 ||
		!validEvidenceReceiptNodeID(request.ReceiptNodeID) ||
		request.ReceiptEpoch == 0 ||
		!ValidSHA256Digest(request.PublicKeySHA256) {
		return errors.New("executor evidence poll request is invalid")
	}
	return nil
}

func (response ExecutorEvidencePollResponseV1) Validate() error {
	if response.ProtocolVersion != ExecutorEvidenceProtocolV1 || !validEvidenceChallenge(response.Challenge) {
		return errors.New("executor evidence poll response is invalid")
	}
	return response.Status.Validate()
}

func (report ExecutorEvidenceReportV1) Validate() error {
	_, err := report.DecodeFrames()
	return err
}

// DecodeFrames returns independent copies of the exact length-prefixed signed
// frames after enforcing the per-report count and decoded-byte limits.
func (report ExecutorEvidenceReportV1) DecodeFrames() ([][]byte, error) {
	if report.ProtocolVersion != ExecutorEvidenceProtocolV1 {
		return nil, errors.New("executor evidence report protocol version is invalid")
	}
	if err := report.HeadProof.Validate(); err != nil {
		return nil, err
	}
	frames, err := decodeExecutorEvidenceFrames(report.SignedFramesBase64)
	if err != nil {
		return nil, err
	}
	claim := report.HeadProof.Claim
	if uint32(len(frames)) != claim.FrameCount ||
		ExecutorEvidenceFramesDigestV1(frames) != claim.FramesDigest {
		return nil, errors.New("executor evidence report frames do not match the signed frame binding")
	}
	return frames, nil
}

func (response ExecutorEvidenceReportResponseV1) Validate() error {
	if response.ProtocolVersion != ExecutorEvidenceProtocolV1 {
		return errors.New("executor evidence report response protocol version is invalid")
	}
	return response.Status.Validate()
}

func (finding ExecutorEvidenceFindingV1) Validate() error {
	if !validCanonicalEvidenceTime(finding.DetectedAt) {
		return errors.New("executor evidence finding timestamp is invalid")
	}
	if err := finding.ComparedHead.Validate(); err != nil {
		return err
	}
	if err := finding.ObservedHead.Validate(); err != nil {
		return err
	}
	if !sameExecutorEvidenceIdentity(finding.ComparedHead, finding.ObservedHead) {
		return errors.New("executor evidence finding changed the compared receipt identity")
	}
	switch finding.Kind {
	case ExecutorEvidenceFindingRollback:
		if finding.ObservedHead.Sequence >= finding.ComparedHead.Sequence {
			return errors.New("executor evidence rollback finding is not lower than the compared checkpoint")
		}
	case ExecutorEvidenceFindingEquivocation:
		if finding.ObservedHead.Sequence < finding.ComparedHead.Sequence ||
			(finding.ObservedHead.Sequence == finding.ComparedHead.Sequence &&
				finding.ObservedHead.ChainHash == finding.ComparedHead.ChainHash) {
			return errors.New("executor evidence equivocation finding does not conflict with the compared checkpoint")
		}
	default:
		return errors.New("executor evidence finding kind is invalid")
	}
	return nil
}

func (status ExecutorEvidenceStatusV1) Validate() error {
	switch status.State {
	case ExecutorEvidenceStatusUnwitnessed:
		if status.Head != nil || status.WitnessedAt != "" || status.Finding != nil {
			return errors.New("unwitnessed executor evidence status contains a checkpoint")
		}
		return nil
	case ExecutorEvidenceStatusCurrent:
		if status.Head == nil || status.Finding != nil || !validCanonicalEvidenceTime(status.WitnessedAt) {
			return errors.New("executor evidence checkpoint status is incomplete")
		}
	case ExecutorEvidenceStatusRollbackDetected, ExecutorEvidenceStatusEquivocationDetected:
		if status.Head == nil || status.Finding == nil || !validCanonicalEvidenceTime(status.WitnessedAt) {
			return errors.New("executor evidence finding status is incomplete")
		}
		if status.State == ExecutorEvidenceStatusRollbackDetected && status.Finding.Kind != ExecutorEvidenceFindingRollback ||
			status.State == ExecutorEvidenceStatusEquivocationDetected && status.Finding.Kind != ExecutorEvidenceFindingEquivocation {
			return errors.New("executor evidence finding does not match its status")
		}
	default:
		return errors.New("executor evidence status state is invalid")
	}
	if err := status.Head.Validate(); err != nil {
		return err
	}
	if status.Finding == nil {
		return nil
	}
	if err := status.Finding.Validate(); err != nil {
		return err
	}
	compared := status.Finding.ComparedHead
	if !sameExecutorEvidenceIdentity(*status.Head, compared) {
		return errors.New("executor evidence finding changed the pinned receipt identity")
	}
	if status.Head.Sequence < compared.Sequence ||
		(status.Head.Sequence == compared.Sequence && status.Head.ChainHash != compared.ChainHash) {
		return errors.New("executor evidence checkpoint predates or conflicts with the finding comparison checkpoint")
	}
	detected, _ := time.Parse(time.RFC3339Nano, status.Finding.DetectedAt)
	witnessed, _ := time.Parse(time.RFC3339Nano, status.WitnessedAt)
	// When Head is later than ComparedHead, a report may have proven the
	// finding before a racing sibling report advanced the retained checkpoint.
	// Only equal coordinates describe the same witnessed checkpoint and require
	// finding detection to be at or after its timestamp.
	if detected.Before(witnessed) && status.Head.Sequence == compared.Sequence {
		return errors.New("executor evidence finding predates the retained checkpoint")
	}
	return nil
}

func (inspection ExecutorEvidenceInspectionV1) Validate() error {
	if inspection.ProtocolVersion != ExecutorEvidenceProtocolV1 ||
		!validEvidenceIdentity(inspection.ControllerInstanceID, 128) ||
		!validEvidenceIdentity(inspection.ControlNodeID, 128) {
		return errors.New("executor evidence inspection identity is invalid")
	}
	if err := inspection.Status.Validate(); err != nil {
		return err
	}
	if inspection.IdentityProof == nil {
		if inspection.Status.State != ExecutorEvidenceStatusUnwitnessed {
			return errors.New("witnessed executor evidence inspection omits its identity proof")
		}
		return nil
	}
	if inspection.Status.State == ExecutorEvidenceStatusUnwitnessed {
		return errors.New("unwitnessed executor evidence inspection contains an identity proof")
	}
	if err := inspection.IdentityProof.Validate(); err != nil {
		return err
	}
	claim := inspection.IdentityProof.Claim
	if claim.ControllerInstanceID != inspection.ControllerInstanceID || claim.ControlNodeID != inspection.ControlNodeID {
		return errors.New("executor evidence inspection does not match its enrolled identity")
	}
	if inspection.Status.Head == nil {
		return errors.New("witnessed executor evidence inspection omits its checkpoint")
	}
	head := *inspection.Status.Head
	if head.Stream != claim.Stream || head.ReceiptNodeID != claim.ReceiptNodeID ||
		head.ReceiptEpoch != claim.ReceiptEpoch || head.PublicKeySHA256 != claim.PublicKeySHA256 {
		return errors.New("executor evidence inspection checkpoint does not match its enrolled identity")
	}
	return nil
}

func (statement ExecutorEvidenceExportStatementV1) Validate() error {
	if statement.ProtocolVersion != ExecutorEvidenceProtocolV1 ||
		!validEvidenceIdentity(statement.ControllerInstanceID, 128) ||
		!validEvidenceIdentity(statement.ControlNodeID, 128) ||
		!validCanonicalEvidenceTime(statement.ExportedAt) {
		return errors.New("executor evidence export statement is invalid")
	}
	if err := statement.IdentityProof.Validate(); err != nil {
		return err
	}
	claim := statement.IdentityProof.Claim
	if claim.ControllerInstanceID != statement.ControllerInstanceID || claim.ControlNodeID != statement.ControlNodeID {
		return errors.New("executor evidence export identity does not match the controller statement")
	}
	if err := statement.Status.Validate(); err != nil {
		return err
	}
	if statement.Status.Head != nil {
		head := *statement.Status.Head
		if head.Stream != claim.Stream || head.ReceiptNodeID != claim.ReceiptNodeID ||
			head.ReceiptEpoch != claim.ReceiptEpoch || head.PublicKeySHA256 != claim.PublicKeySHA256 {
			return errors.New("executor evidence export checkpoint does not match the enrolled identity")
		}
	}
	exported, _ := time.Parse(time.RFC3339Nano, statement.ExportedAt)
	if statement.Status.WitnessedAt != "" {
		witnessed, _ := time.Parse(time.RFC3339Nano, statement.Status.WitnessedAt)
		if exported.Before(witnessed) {
			return errors.New("executor evidence export predates its checkpoint")
		}
	}
	if statement.Status.Finding != nil {
		detected, _ := time.Parse(time.RFC3339Nano, statement.Status.Finding.DetectedAt)
		if exported.Before(detected) {
			return errors.New("executor evidence export predates its finding")
		}
	}
	return nil
}

// ExecutorEvidenceExportSigningStatementV1 returns the exact purpose-separated
// bytes signed by the controller witness key.
func ExecutorEvidenceExportSigningStatementV1(statement ExecutorEvidenceExportStatementV1) ([]byte, error) {
	if err := statement.Validate(); err != nil {
		return nil, err
	}
	identityStatement, _ := ExecutorEvidenceIdentityProofStatementV1(statement.IdentityProof.Claim)
	status := statement.Status
	out := append([]byte(nil), executorEvidenceExportDomainV1...)
	out = appendEvidenceText(out, ExecutorEvidenceExportPayloadTypeV1)
	out = appendEvidenceUint64(out, uint64(statement.ProtocolVersion))
	out = appendEvidenceText(out, statement.ControllerInstanceID)
	out = appendEvidenceText(out, statement.ControlNodeID)
	out = appendEvidenceBytes(out, identityStatement)
	out = appendEvidenceText(out, statement.IdentityProof.SignatureBase64)
	out = appendEvidenceText(out, status.State)
	out = appendEvidenceOptionalHead(out, status.Head)
	out = appendEvidenceText(out, status.WitnessedAt)
	if status.Finding == nil {
		out = append(out, 0)
	} else {
		out = append(out, 1)
		out = appendEvidenceText(out, status.Finding.Kind)
		out = appendEvidenceText(out, status.Finding.DetectedAt)
		out = appendEvidenceHead(out, status.Finding.ComparedHead)
		out = appendEvidenceHead(out, status.Finding.ObservedHead)
	}
	out = appendEvidenceText(out, statement.ExportedAt)
	return out, nil
}

func SignExecutorEvidenceExportV1(statement ExecutorEvidenceExportStatementV1, private ed25519.PrivateKey) (ExecutorEvidenceExportV1, error) {
	if len(private) != ed25519.PrivateKeySize {
		return ExecutorEvidenceExportV1{}, errors.New("executor evidence witness private key has invalid length")
	}
	public := private.Public().(ed25519.PublicKey)
	if statement.IdentityProof.Claim.PublicKeySHA256 == ExecutorEvidencePublicKeySHA256(public) {
		return ExecutorEvidenceExportV1{}, errors.New("executor evidence witness key must be distinct from the receipt key")
	}
	signingStatement, err := ExecutorEvidenceExportSigningStatementV1(statement)
	if err != nil {
		return ExecutorEvidenceExportV1{}, err
	}
	return ExecutorEvidenceExportV1{
		PayloadType: ExecutorEvidenceExportPayloadTypeV1, Statement: statement,
		WitnessPublicKeyBase64: base64.StdEncoding.EncodeToString(public),
		WitnessPublicKeySHA256: ExecutorEvidencePublicKeySHA256(public),
		SignatureBase64:        base64.StdEncoding.EncodeToString(ed25519.Sign(private, signingStatement)),
	}, nil
}

func (export ExecutorEvidenceExportV1) Validate() error {
	if export.PayloadType != ExecutorEvidenceExportPayloadTypeV1 {
		return errors.New("executor evidence export payload type is invalid")
	}
	if err := export.Statement.Validate(); err != nil {
		return err
	}
	public, err := executorEvidencePublicKey(export.WitnessPublicKeyBase64, export.WitnessPublicKeySHA256)
	if err != nil {
		return err
	}
	if export.WitnessPublicKeySHA256 == export.Statement.IdentityProof.Claim.PublicKeySHA256 {
		return errors.New("executor evidence witness key is not purpose-separated from the receipt key")
	}
	signature, err := canonicalEvidenceSignature(export.SignatureBase64)
	if err != nil {
		return err
	}
	statement, err := ExecutorEvidenceExportSigningStatementV1(export.Statement)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, statement, signature) {
		return errors.New("executor evidence export signature is invalid")
	}
	return nil
}

// VerifyExecutorEvidenceExportV1 verifies the complete export and requires the
// caller's out-of-band trusted witness key to match the embedded public key.
func VerifyExecutorEvidenceExportV1(export ExecutorEvidenceExportV1, trusted ed25519.PublicKey) error {
	if len(trusted) != ed25519.PublicKeySize {
		return errors.New("trusted executor evidence witness key has invalid length")
	}
	if err := export.Validate(); err != nil {
		return err
	}
	public, _ := executorEvidencePublicKey(export.WitnessPublicKeyBase64, export.WitnessPublicKeySHA256)
	if !bytes.Equal(public, trusted) {
		return errors.New("executor evidence export was not signed by the trusted witness key")
	}
	return nil
}

func DecodeExecutorEvidenceIdentityProofV1(raw []byte) (ExecutorEvidenceIdentityProofV1, error) {
	var value ExecutorEvidenceIdentityProofV1
	err := decodeExecutorEvidenceJSON(raw, &value, func() error { return value.Validate() })
	return value, err
}

func DecodeExecutorEvidencePollRequestV1(raw []byte) (ExecutorEvidencePollRequestV1, error) {
	var value ExecutorEvidencePollRequestV1
	err := decodeExecutorEvidenceJSON(raw, &value, func() error { return value.Validate() })
	return value, err
}

func DecodeExecutorEvidencePollResponseV1(raw []byte) (ExecutorEvidencePollResponseV1, error) {
	var value ExecutorEvidencePollResponseV1
	err := decodeExecutorEvidenceJSON(raw, &value, func() error { return value.Validate() })
	return value, err
}

func DecodeExecutorEvidenceReportV1(raw []byte) (ExecutorEvidenceReportV1, error) {
	var value ExecutorEvidenceReportV1
	err := decodeExecutorEvidenceJSON(raw, &value, func() error { return value.Validate() })
	return value, err
}

func DecodeExecutorEvidenceReportResponseV1(raw []byte) (ExecutorEvidenceReportResponseV1, error) {
	var value ExecutorEvidenceReportResponseV1
	err := decodeExecutorEvidenceJSON(raw, &value, func() error { return value.Validate() })
	return value, err
}

func DecodeExecutorEvidenceInspectionV1(raw []byte) (ExecutorEvidenceInspectionV1, error) {
	var value ExecutorEvidenceInspectionV1
	err := decodeExecutorEvidenceJSON(raw, &value, func() error { return value.Validate() })
	return value, err
}

func DecodeExecutorEvidenceExportV1(raw []byte) (ExecutorEvidenceExportV1, error) {
	var value ExecutorEvidenceExportV1
	err := decodeExecutorEvidenceJSON(raw, &value, func() error { return value.Validate() })
	return value, err
}

// EncodeExecutorEvidenceChallengeV1 returns the only accepted challenge
// representation: unpadded URL-safe base64 of 32 through 256 opaque bytes.
func EncodeExecutorEvidenceChallengeV1(raw []byte) (string, error) {
	if len(raw) < sha256.Size || len(raw) > MaxExecutorEvidenceChallenge {
		return "", fmt.Errorf("executor evidence challenge must contain %d through %d bytes", sha256.Size, MaxExecutorEvidenceChallenge)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeExecutorEvidenceChallengeV1(value string) ([]byte, error) {
	if !validEvidenceChallenge(value) {
		return nil, errors.New("executor evidence challenge is not canonical")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(value)
	return raw, nil
}

// ExecutorEvidenceFramesDigestV1 returns the canonical domain-separated digest
// of the exact decoded native frames. It hashes frame count, each frame length,
// and each frame byte; JSON and base64 encodings are deliberately excluded.
func ExecutorEvidenceFramesDigestV1(frames [][]byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(executorEvidenceFramesDigestDomainV1))
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

// ExecutorEvidencePublicKeySHA256 returns the full, lowercase SHA-256 digest of
// an Ed25519 public key. It deliberately does not use evidence.KeyID, whose
// shorter display identifier is insufficient for a trust pin.
func ExecutorEvidencePublicKeySHA256(public ed25519.PublicKey) string {
	if len(public) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeExecutorEvidenceJSON(raw []byte, destination any, validate func() error) error {
	if err := dsse.DecodeStrictInto(raw, MaxExecutorEvidenceJSONBytes, destination); err != nil {
		return err
	}
	return validate()
}

func decodeExecutorEvidenceFrames(encoded []string) ([][]byte, error) {
	if len(encoded) > MaxExecutorEvidenceFrames {
		return nil, fmt.Errorf("executor evidence report contains %d frames, limit is %d", len(encoded), MaxExecutorEvidenceFrames)
	}
	frames := make([][]byte, 0, len(encoded))
	for index, value := range encoded {
		if value == "" || len(value) > base64.StdEncoding.EncodedLen(MaxExecutorEvidenceFrameBytes) {
			return nil, fmt.Errorf("executor evidence frame %d is empty or exceeds its limit", index)
		}
		frame, err := base64.StdEncoding.DecodeString(value)
		if err != nil || base64.StdEncoding.EncodeToString(frame) != value {
			return nil, fmt.Errorf("executor evidence frame %d is not canonical base64", index)
		}
		frames = append(frames, frame)
	}
	if err := validateExecutorEvidenceDecodedFrames(frames); err != nil {
		return nil, err
	}
	return frames, nil
}

func validateExecutorEvidenceDecodedFrames(frames [][]byte) error {
	if len(frames) > MaxExecutorEvidenceFrames {
		return fmt.Errorf("executor evidence report contains %d frames, limit is %d", len(frames), MaxExecutorEvidenceFrames)
	}
	total := 0
	for index, frame := range frames {
		if len(frame) < 5 || len(frame) > MaxExecutorEvidenceFrameBytes {
			return fmt.Errorf("executor evidence frame %d has invalid length", index)
		}
		envelopeBytes := binary.BigEndian.Uint32(frame[:4])
		if envelopeBytes == 0 || envelopeBytes > 64<<10 || uint64(envelopeBytes) != uint64(len(frame)-4) {
			return fmt.Errorf("executor evidence frame %d has an invalid length prefix", index)
		}
		total += len(frame)
		if total > MaxExecutorEvidenceDecodedBytes {
			return fmt.Errorf("executor evidence frames exceed %d decoded bytes", MaxExecutorEvidenceDecodedBytes)
		}
	}
	return nil
}

func executorEvidencePublicKey(encoded, digest string) (ed25519.PublicKey, error) {
	if encoded == "" || len(encoded) != base64.StdEncoding.EncodedLen(ed25519.PublicKeySize) ||
		!ValidSHA256Digest(digest) {
		return nil, errors.New("executor evidence public key encoding or digest is invalid")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("executor evidence public key is not canonical base64")
	}
	public := ed25519.PublicKey(append([]byte(nil), raw...))
	if ExecutorEvidencePublicKeySHA256(public) != digest {
		return nil, errors.New("executor evidence public key digest does not match the key")
	}
	return public, nil
}

func canonicalEvidenceSignature(encoded string) ([]byte, error) {
	if encoded == "" || len(encoded) != base64.StdEncoding.EncodedLen(ed25519.SignatureSize) {
		return nil, errors.New("executor evidence signature length is invalid")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("executor evidence signature is not canonical base64")
	}
	return raw, nil
}

func validEvidenceChallenge(value string) bool {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(MaxExecutorEvidenceChallenge) ||
		strings.Contains(value, "=") {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) >= sha256.Size && len(raw) <= MaxExecutorEvidenceChallenge &&
		base64.RawURLEncoding.EncodeToString(raw) == value
}

func validEvidenceIdentity(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validEvidenceReceiptNodeID(value string) bool {
	return len(value) <= 256 && utf8.ValidString(value) && boundedText(value, 256) &&
		strings.TrimSpace(value) == value
}

func validCanonicalEvidenceTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.IsZero() && value == parsed.UTC().Format(time.RFC3339Nano)
}

func sameExecutorEvidenceIdentity(left, right ExecutorEvidenceHeadV1) bool {
	return left.Stream == right.Stream && left.ReceiptNodeID == right.ReceiptNodeID &&
		left.ReceiptEpoch == right.ReceiptEpoch && left.PublicKeySHA256 == right.PublicKeySHA256
}

func zeroExecutorEvidenceChainHash() string {
	return "sha256:" + strings.Repeat("0", sha256.Size*2)
}

func appendEvidenceText(destination []byte, value string) []byte {
	return appendEvidenceBytes(destination, []byte(value))
}

func appendEvidenceBytes(destination, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func appendEvidenceUint64(destination []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(destination, encoded[:]...)
}

func appendEvidenceOptionalHead(destination []byte, head *ExecutorEvidenceHeadV1) []byte {
	if head == nil {
		return append(destination, 0)
	}
	destination = append(destination, 1)
	return appendEvidenceHead(destination, *head)
}

func appendEvidenceHead(destination []byte, head ExecutorEvidenceHeadV1) []byte {
	destination = appendEvidenceText(destination, head.Stream)
	destination = appendEvidenceText(destination, head.ReceiptNodeID)
	destination = appendEvidenceUint64(destination, head.ReceiptEpoch)
	destination = appendEvidenceUint64(destination, head.Sequence)
	destination = appendEvidenceText(destination, head.ChainHash)
	return appendEvidenceText(destination, head.PublicKeySHA256)
}
