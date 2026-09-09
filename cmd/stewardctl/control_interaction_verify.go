package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/hardrails/steward/internal/interactionpermit"
	"github.com/hardrails/steward/internal/securefile"
)

// controlInteractionVerifyResponse is offline verification, not consent or
// delivery. Callers must compare the returned statement to their independently
// retained runtime and question before using the separate keyless courier.
func controlInteractionVerifyResponse(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control interaction verify-response", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	permitPath := flags.String("permit-file", "", "owner-only signed interaction permit")
	responsePath := flags.String("response-file", "", "owner-only exact response body")
	publicPath := flags.String("public-key", "", "independently pinned base64 Ed25519 public key")
	keyID := flags.String("key-id", "", "independently pinned task-authority key ID")
	maxValidity := flags.Duration("max-validity", interactionpermit.MaxValidity, "local maximum response validity")
	at := flags.String("at", "", "canonical UTC RFC3339-seconds evaluation time")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *permitPath == "" || *responsePath == "" || *publicPath == "" || *keyID == "" || flags.NArg() != 0 {
		return errors.New("interaction verify-response requires -permit-file, -response-file, -public-key, and -key-id")
	}
	public, err := readPublicKey(*publicPath)
	if err != nil {
		return err
	}
	evaluatedAt, err := permitEvaluationTime(*at)
	if err != nil {
		return err
	}
	permit, err := securefile.Read(*permitPath, interactionpermit.MaxEnvelopeBytes, securefile.OwnerOnly)
	if err != nil {
		return err
	}
	verified, err := interactionpermit.Verify(
		permit, map[string]ed25519.PublicKey{*keyID: public}, evaluatedAt, *maxValidity,
	)
	if err != nil {
		return err
	}
	response, err := securefile.Read(*responsePath, interactionpermit.MaxResponseBytes, securefile.OwnerOnly)
	if err != nil {
		return err
	}
	if int64(len(response)) != verified.Statement.ResponseBytes ||
		interactionpermit.ResponseDigest(response) != verified.Statement.ResponseDigest {
		return errors.New("interaction permit does not bind the supplied exact answer bytes")
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		Valid          bool                        `json:"valid"`
		EvaluatedAt    string                      `json:"evaluated_at"`
		KeyID          string                      `json:"key_id"`
		EnvelopeDigest string                      `json:"envelope_digest"`
		Statement      interactionpermit.Statement `json:"statement"`
	}{true, evaluatedAt.Format(time.RFC3339), verified.KeyID, verified.EnvelopeDigest, verified.Statement})
}
