package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
)

type responseIssuerRequest struct {
	Interaction    controlprotocol.InteractionRequestV1 `json:"interaction"`
	ResponseBase64 string                               `json:"response_base64"`
}

// issueResponse signs content supplied by the trusted host, not business
// approval. The native request validator binds the whole question; Gateway
// independently checks that this exact question is pending before delivery.
func (issuer *taskIssuer) issueResponse(request responseIssuerRequest) ([]byte, error) {
	if !issuer.mu.TryLock() {
		return nil, errTaskIssuerBusy
	}
	defer issuer.mu.Unlock()
	if issuer.root == nil {
		return nil, errTaskIssuerBusy
	}
	if !issuer.config.AllowResponses {
		return nil, errors.New("response issuance is not enabled")
	}
	question := request.Interaction
	if err := question.Validate(); err != nil {
		return nil, err
	}
	admitted, intent := issuer.admitted, issuer.intent
	if question.TenantID != intent.TenantID || question.NodeID != intent.NodeID ||
		question.InstanceID != intent.InstanceID || question.Generation != intent.Generation ||
		question.Generation != admitted.Generation || question.RuntimeRef != admitted.RuntimeRef ||
		question.GrantID != admitted.GrantID || question.CapsuleDigest != intent.CapsuleDigest ||
		question.CapsuleDigest != admitted.CapsuleDigest || question.PolicyDigest != admitted.PolicyDigest {
		return nil, errors.New("interaction does not belong to the station's pinned runtime")
	}
	response, err := base64.StdEncoding.Strict().DecodeString(request.ResponseBase64)
	if err != nil || len(response) == 0 || len(response) > interactionpermit.MaxResponseBytes ||
		base64.StdEncoding.EncodeToString(response) != request.ResponseBase64 {
		return nil, errors.New("response is not bounded canonical base64")
	}
	var body interactionpermit.ResponseBody
	if err = dsse.DecodeStrictInto(response, interactionpermit.MaxResponseBytes, &body); err != nil {
		return nil, err
	}
	if err = body.Validate(question.Options, question.AllowText); err != nil {
		return nil, err
	}
	statement := interactionpermit.Statement{
		SchemaVersion: interactionpermit.SchemaV1,
		TenantID:      intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
		Generation: intent.Generation, RuntimeRef: admitted.RuntimeRef, GrantID: admitted.GrantID,
		CapsuleDigest: admitted.CapsuleDigest, PolicyDigest: admitted.PolicyDigest,
		InteractionID: question.InteractionID, RequestDigest: question.RequestDigest,
		ResponseDigest: interactionpermit.ResponseDigest(response), ResponseBytes: int64(len(response)),
	}
	// The NUL prefix cannot occur in a valid task ID. No task can occupy a
	// response's record, and changing the question cannot buy a second answer.
	digest := sha256.Sum256([]byte("\x00interaction-response\x00" + question.InteractionID))
	name := hex.EncodeToString(digest[:]) + ".json"
	match := func(raw []byte) error { return issuer.matchResponse(raw, statement, question.ExpiresAt) }
	if retained, found, err := issuer.recover(name, interactionpermit.MaxEnvelopeBytes, match); found || err != nil {
		return retained, err
	}
	now := timeNow().UTC().Truncate(time.Second)
	expires, _ := time.Parse(time.RFC3339, question.ExpiresAt) // Validated above.
	if !now.Before(expires) {
		return nil, errors.New("interaction has expired")
	}
	// Clock skew is inside, not added to, the station's configured validity.
	notBefore := now.Add(-5 * time.Second)
	if limit := notBefore.Add(issuer.config.Validity); expires.After(limit) {
		expires = limit
	}
	statement.NotBefore, statement.ExpiresAt = notBefore.Format(time.RFC3339), expires.Format(time.RFC3339)
	private, err := readPrivateKey(filepath.Join(issuer.snapshots, "key"))
	if err != nil {
		return nil, errors.Join(errTaskIssuerPreparation, err)
	}
	defer clear(private)
	permit, err := interactionpermit.Sign(statement, issuer.config.KeyID, private)
	if err != nil {
		return nil, errors.Join(errTaskIssuerPreparation, err)
	}
	if err = match(permit); err != nil {
		return nil, errors.Join(errTaskIssuerPreparation, err)
	}
	issuer.count++ // Ambiguous persistence consumes capacity; never replace it.
	if err = issuer.write(name, permit); err != nil {
		return nil, errors.Join(errTaskIssuerStorage, err)
	}
	return permit, nil
}

func (issuer *taskIssuer) matchResponse(raw []byte, expected interactionpermit.Statement, expiresAt string) error {
	verified, err := interactionpermit.Verify(raw,
		map[string]ed25519.PublicKey{issuer.config.KeyID: issuer.public}, timeNow().UTC(), issuer.config.Validity)
	if err != nil {
		return err
	}
	expected.NotBefore, expected.ExpiresAt = verified.Statement.NotBefore, verified.Statement.ExpiresAt
	if verified.Statement != expected || verified.Statement.ExpiresAt > expiresAt {
		return errTaskIssuerConflict
	}
	return nil
}
