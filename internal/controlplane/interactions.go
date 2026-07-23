package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
)

type interactionPage struct {
	Interactions []controlstore.Interaction `json:"interactions"`
	NextAfter    string                     `json:"next_after,omitempty"`
}

type interactionResponseSubmit struct {
	PermitBase64   string `json:"permit_base64"`
	ResponseBase64 string `json:"response_base64"`
}

func (server *Server) executorInteractions(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	raw, ok := server.readBody(writer, request)
	if !ok {
		return
	}
	var batch controlprotocol.InteractionRequestBatchV1
	if dsse.DecodeStrictInto(raw, maxRequestBytes, &batch) != nil ||
		batch.Validate() != nil || batch.NodeID != identity.NodeID {
		writeError(writer, http.StatusBadRequest, "invalid_request", "executor interaction batch is invalid")
		return
	}
	applied, err := server.store.RetainInteractions(identity, batch, server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Applied int `json:"applied"`
	}{Applied: applied})
}

func (server *Server) executorInteractionResponsePoll(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	raw, ok := server.readBody(writer, request)
	if !ok {
		return
	}
	var poll controlprotocol.InteractionResponsePollRequestV1
	if dsse.DecodeStrictInto(raw, maxRequestBytes, &poll) != nil ||
		poll.Validate() != nil || poll.NodeID != identity.NodeID {
		writeError(writer, http.StatusBadRequest, "invalid_request", "executor interaction response poll is invalid")
		return
	}
	deliveries, err := server.store.PollInteractionResponses(identity, server.now(), poll.Limit)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, controlprotocol.InteractionResponsePollResponseV1{
		SchemaVersion: controlprotocol.InteractionPollSchemaV1,
		Deliveries:    deliveries,
	})
}

func (server *Server) executorInteractionResponseAck(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	var ack controlprotocol.InteractionResponseAckV1
	if !server.decode(writer, request, &ack) {
		return
	}
	applied, err := server.store.AckInteractionResponse(identity, ack, server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Applied bool `json:"applied"`
	}{Applied: applied})
}

func (server *Server) interactions(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	page, ok := parsePage(writer, request)
	if !ok {
		return
	}
	if page.limit > 100 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "interaction limit must be between 1 and 100")
		return
	}
	values, err := server.store.ListInteractions(identity, request.PathValue("tenant_id"), server.now())
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	selected, next, err := pageInteractions(values, page)
	if err != nil {
		if errors.Is(err, controlstore.ErrInvalid) {
			writeError(writer, http.StatusBadRequest, "invalid_request", "after cursor does not identify a retained interaction")
			return
		}
		server.logger.Error("control interaction page exceeded response bound", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not encode a bounded interaction page")
		return
	}
	writeJSON(writer, http.StatusOK, interactionPage{Interactions: selected, NextAfter: next})
}

func (server *Server) interaction(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) {
		return
	}
	if !emptyInteractionBody(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	value, found, err := server.store.GetInteraction(
		identity, request.PathValue("tenant_id"), request.PathValue("interaction_id"), server.now(),
	)
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	if !found {
		writeError(writer, http.StatusNotFound, "not_found", "interaction was not found")
		return
	}
	writeJSON(writer, http.StatusOK, value)
}

func (server *Server) interactionResponse(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	var input interactionResponseSubmit
	if !server.decode(writer, request, &input) {
		return
	}
	permit, permitErr := base64.StdEncoding.DecodeString(input.PermitBase64)
	response, responseErr := base64.StdEncoding.DecodeString(input.ResponseBase64)
	if permitErr != nil || responseErr != nil ||
		base64.StdEncoding.EncodeToString(permit) != input.PermitBase64 ||
		base64.StdEncoding.EncodeToString(response) != input.ResponseBase64 ||
		len(permit) == 0 || len(permit) > interactionpermit.MaxEnvelopeBytes ||
		len(response) == 0 || len(response) > interactionpermit.MaxResponseBytes {
		writeError(writer, http.StatusBadRequest, "invalid_request", "interaction response courier encoding is invalid")
		return
	}
	value, created, err := server.store.SubmitInteractionResponse(identity, controlstore.InteractionResponseInput{
		TenantID: request.PathValue("tenant_id"), InteractionID: request.PathValue("interaction_id"),
		Permit: permit, Response: response,
	}, server.now())
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusAccepted
	}
	writeJSON(writer, status, value)
}

func pageInteractions(
	values []controlstore.Interaction,
	page pageRequest,
) ([]controlstore.Interaction, string, error) {
	start := 0
	if page.after != "" {
		found := false
		for index, interaction := range values {
			if interaction.InteractionID == page.after {
				start, found = index+1, true
				break
			}
		}
		if !found {
			return nil, "", controlstore.ErrInvalid
		}
	}
	selected := make([]controlstore.Interaction, 0, min(page.limit, len(values)-start))
	for index := start; index < len(values) && len(selected) < page.limit; index++ {
		candidate := append(append([]controlstore.Interaction(nil), selected...), values[index])
		next := ""
		if index+1 < len(values) {
			next = values[index].InteractionID
		}
		raw, err := json.Marshal(interactionPage{Interactions: candidate, NextAfter: next})
		if err != nil {
			return nil, "", err
		}
		if len(raw)+1 > maxResponseBytes {
			if len(selected) == 0 {
				return nil, "", errors.New("one valid interaction cannot fit the response limit")
			}
			break
		}
		selected = candidate
	}
	next := ""
	if start+len(selected) < len(values) {
		next = selected[len(selected)-1].InteractionID
	}
	return selected, next, nil
}

func emptyInteractionBody(writer http.ResponseWriter, request *http.Request) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, 1)
	body, err := io.ReadAll(request.Body)
	if err != nil || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(body) != 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "interaction lookup must not include a body")
		return false
	}
	return true
}
