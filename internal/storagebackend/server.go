package storagebackend

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
)

const MaxWireBytes = 64 << 10

type handler struct {
	backend   Backend
	tokenHash [sha256.Size]byte
}

// NewHandler exposes one Backend through a finite authenticated JSON protocol.
// Deployments bind it to an owner-only Unix socket; the bearer is a second
// boundary against accidental access by another local process.
func NewHandler(backend Backend, token string) (http.Handler, error) {
	if backend == nil || !validToken(token) {
		return nil, errors.New("storage backend handler requires a backend and bounded bearer")
	}
	return &handler{backend: backend, tokenHash: sha256.Sum256([]byte(token))}, nil
}

func (service *handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	defer func() {
		if recover() != nil {
			writeBackendError(writer, http.StatusInternalServerError, "internal_error", "storage backend operation panicked")
		}
	}()
	if request.URL.RawQuery != "" {
		writeBackendError(writer, http.StatusBadRequest, "invalid_request", "storage backend requests do not accept query parameters")
		return
	}
	if !service.authorized(request) {
		writeBackendError(writer, http.StatusUnauthorized, "unauthorized", "valid storage backend bearer required")
		return
	}

	switch request.Method + " " + request.URL.Path {
	case http.MethodGet + " /v1/capabilities":
		service.capabilities(writer, request)
	case http.MethodPost + " /v1/volumes/inspect":
		serveBackendOperation(writer, request, service.backend.InspectVolume)
	case http.MethodPost + " /v1/volumes/create":
		serveBackendMutation(writer, request, service.backend.CreateVolume, "volume")
	case http.MethodPost + " /v1/volumes/delete":
		serveBackendMutation(writer, request, service.backend.DeleteVolume, "volume")
	case http.MethodPost + " /v1/snapshots/inspect":
		serveBackendOperation(writer, request, service.backend.InspectSnapshot)
	case http.MethodPost + " /v1/snapshots/create":
		serveBackendMutation(writer, request, service.backend.CreateSnapshot, "snapshot")
	case http.MethodPost + " /v1/snapshots/clone":
		serveBackendMutation(writer, request, service.backend.CloneVolume, "volume")
	case http.MethodPost + " /v1/snapshots/delete":
		serveBackendMutation(writer, request, service.backend.DeleteSnapshot, "snapshot")
	default:
		writeBackendError(writer, http.StatusNotFound, "not_found", "storage backend operation not found")
	}
}

func (service *handler) authorized(request *http.Request) bool {
	header := request.Header.Values("Authorization")
	if len(header) != 1 || !strings.HasPrefix(header[0], "Bearer ") {
		return false
	}
	presented := strings.TrimPrefix(header[0], "Bearer ")
	if !validToken(presented) {
		return false
	}
	digest := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(digest[:], service.tokenHash[:]) == 1
}

func (service *handler) capabilities(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, 1)
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) != 0 {
		writeBackendError(writer, http.StatusBadRequest, "invalid_request", "capabilities request must not contain a body")
		return
	}
	capabilities, err := service.backend.Capabilities(request.Context())
	if err != nil {
		writeMappedBackendError(writer, err)
		return
	}
	if err := capabilities.Validate(); err != nil {
		writeBackendError(writer, http.StatusBadGateway, "invalid_backend_response", "storage backend returned invalid capabilities")
		return
	}
	writeBackendJSON(writer, http.StatusOK, capabilities)
}

type validRequest interface{ Validate() error }
type validProjection interface{ Validate() error }

func serveBackendOperation[Request validRequest, Result validProjection](
	writer http.ResponseWriter,
	request *http.Request,
	operation func(context.Context, Request) (Result, error),
) {
	input, ok := decodeBackendRequest[Request](writer, request)
	if !ok {
		return
	}
	result, err := operation(request.Context(), input)
	if err != nil {
		writeMappedBackendError(writer, err)
		return
	}
	if err := result.Validate(); err != nil {
		writeBackendError(writer, http.StatusBadGateway, "invalid_backend_response", "storage backend returned an invalid object")
		return
	}
	writeBackendJSON(writer, http.StatusOK, result)
}

func serveBackendMutation[Request validRequest, Result validProjection](
	writer http.ResponseWriter,
	request *http.Request,
	operation func(context.Context, Request) (Result, bool, error),
	resultName string,
) {
	input, ok := decodeBackendRequest[Request](writer, request)
	if !ok {
		return
	}
	result, changed, err := operation(request.Context(), input)
	if err != nil {
		writeMappedBackendError(writer, err)
		return
	}
	if err := result.Validate(); err != nil {
		writeBackendError(writer, http.StatusBadGateway, "invalid_backend_response", "storage backend returned an invalid object")
		return
	}
	response := mutationResponse{Changed: changed}
	if resultName == "volume" {
		volume, cast := any(result).(Volume)
		if !cast {
			writeBackendError(writer, http.StatusInternalServerError, "internal_error", "storage backend response type mismatch")
			return
		}
		response.Volume = &volume
	} else {
		snapshot, cast := any(result).(Snapshot)
		if !cast {
			writeBackendError(writer, http.StatusInternalServerError, "internal_error", "storage backend response type mismatch")
			return
		}
		response.Snapshot = &snapshot
	}
	writeBackendJSON(writer, http.StatusOK, response)
}

func decodeBackendRequest[Request validRequest](writer http.ResponseWriter, request *http.Request) (Request, bool) {
	var zero Request
	if mediaType := request.Header.Get("Content-Type"); mediaType != "application/json" {
		writeBackendError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "storage backend request must use application/json")
		return zero, false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, MaxWireBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		writeBackendError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "storage backend request exceeds 64 KiB")
		return zero, false
	}
	var input Request
	if err := dsse.DecodeStrictInto(raw, MaxWireBytes, &input); err != nil || input.Validate() != nil {
		writeBackendError(writer, http.StatusBadRequest, "invalid_request", "storage backend request is invalid")
		return zero, false
	}
	return input, true
}

type mutationResponse struct {
	Volume   *Volume   `json:"volume,omitempty"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
	Changed  bool      `json:"changed"`
}

type wireError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeMappedBackendError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		writeBackendError(writer, http.StatusBadRequest, "invalid_request", "storage backend request is invalid")
	case errors.Is(err, ErrNotFound):
		writeBackendError(writer, http.StatusNotFound, "not_found", "storage backend object not found")
	case errors.Is(err, ErrConflict):
		writeBackendError(writer, http.StatusConflict, "conflict", "storage backend object conflicts with retained state")
	case errors.Is(err, ErrInUse):
		writeBackendError(writer, http.StatusConflict, "in_use", "storage backend object is still referenced")
	case errors.Is(err, ErrCapacity):
		writeBackendError(writer, http.StatusInsufficientStorage, "capacity_exceeded", "storage backend capacity exceeded")
	case errors.Is(err, ErrUnsupported):
		writeBackendError(writer, http.StatusNotImplemented, "unsupported", "storage backend operation is unsupported")
	case errors.Is(err, ErrUnavailable):
		writeBackendError(writer, http.StatusServiceUnavailable, "unavailable", "storage backend is unavailable")
	default:
		writeBackendError(writer, http.StatusInternalServerError, "backend_error", "storage backend operation failed")
	}
}

func writeBackendError(writer http.ResponseWriter, status int, code, message string) {
	writeBackendJSON(writer, status, wireError{Error: code, Message: message})
}

func writeBackendJSON(writer http.ResponseWriter, status int, value any) {
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func validToken(value string) bool {
	return value != "" && len(value) <= 4096 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, " \t\r\n\x00")
}
