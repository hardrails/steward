package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/interactionpermit"
)

func controlInteractionList(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control interaction list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	after := flags.String("after", "", "exclusive interaction ID cursor")
	limit := flags.Int("limit", 100, "maximum interactions to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *limit <= 0 || *limit > 100 || flags.NArg() != 0 {
		return errors.New("control interaction list requires a tenant and a limit between 1 and 100")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListInteractions(ctx, *tenantID, *after, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, page)
}

func controlInteractionShow(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control interaction show", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	interactionID := flags.String("interaction-id", "", "exact interaction identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *interactionID == "" || flags.NArg() != 0 {
		return errors.New("control interaction show requires a tenant and interaction ID")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	interaction, err := client.GetInteraction(ctx, *tenantID, *interactionID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, interaction)
}

func controlInteractionRespond(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control interaction respond", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	interactionID := flags.String("interaction-id", "", "exact interaction identity")
	choice := flags.String("choice", "", "one exact offered choice")
	text := flags.String("text", "", "bounded free-text response when allowed")
	privateKeyPath := flags.String("key", "", "owner-only PEM Ed25519 task-authority private key")
	keyID := flags.String("key-id", "", "admitted task-authority key ID")
	validFor := flags.Duration("valid-for", 15*time.Minute, "maximum response delivery window")
	clockSkew := flags.Duration("clock-skew", 5*time.Second, "bounded allowance for node clock skew")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *interactionID == "" || (*choice == "" && *text == "") ||
		*privateKeyPath == "" || *keyID == "" || flags.NArg() != 0 {
		return errors.New("control interaction respond requires a tenant, interaction ID, choice or text, task key, and key ID")
	}
	if *validFor < time.Second || *validFor > interactionpermit.MaxValidity ||
		*validFor%time.Second != 0 || *clockSkew < 0 || *clockSkew > 5*time.Minute ||
		*clockSkew%time.Second != 0 || *clockSkew >= *validFor {
		return errors.New("interaction response validity and clock skew must be whole seconds within their safe bounds")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	interaction, err := client.GetInteraction(ctx, *tenantID, *interactionID)
	if err != nil {
		return err
	}
	if interaction.State != controlstore.InteractionOpen {
		return fmt.Errorf("interaction is %s, not open", interaction.State)
	}
	responseBody := interactionpermit.ResponseBody{
		SchemaVersion: interactionpermit.ResponseBodySchemaV1,
		Choice:        *choice, Text: *text,
	}
	if err := responseBody.Validate(interaction.Options, interaction.AllowText); err != nil {
		return err
	}
	response, err := json.Marshal(responseBody)
	if err != nil {
		return err
	}
	now := timeNow().UTC().Truncate(time.Second)
	interactionExpires, err := time.Parse(time.RFC3339, interaction.ExpiresAt)
	if err != nil || !now.Before(interactionExpires) {
		return errors.New("interaction has expired")
	}
	expiresAt := now.Add(*validFor)
	if interactionExpires.Before(expiresAt) {
		expiresAt = interactionExpires
	}
	notBefore := now.Add(-*clockSkew)
	if !expiresAt.After(notBefore) {
		return errors.New("interaction expires before a response can be delivered")
	}
	statement := interactionpermit.Statement{
		SchemaVersion: interactionpermit.SchemaV1,
		NodeID:        interaction.NodeID, TenantID: interaction.TenantID,
		InstanceID: interaction.InstanceID, RuntimeRef: interaction.RuntimeRef,
		GrantID: interaction.GrantID, Generation: interaction.Generation,
		CapsuleDigest: interaction.CapsuleDigest, PolicyDigest: interaction.PolicyDigest,
		InteractionID: interaction.InteractionID, RequestDigest: interaction.RequestDigest,
		ResponseDigest: interactionpermit.ResponseDigest(response), ResponseBytes: int64(len(response)),
		NotBefore: notBefore.Format(time.RFC3339), ExpiresAt: expiresAt.Format(time.RFC3339),
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return fmt.Errorf("read task-authority private key: %w", err)
	}
	permit, err := interactionpermit.Sign(statement, *keyID, privateKey)
	if err != nil {
		return err
	}
	queued, err := client.SubmitInteractionResponse(
		ctx, *tenantID, *interactionID, permit, response,
	)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, queued)
}
