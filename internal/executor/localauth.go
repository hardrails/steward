package executor

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// LocalRole limits what one host-local bearer credential may ask Executor to
// do. It does not identify a tenant and never replaces signed admission or an
// authenticated uplink principal.
type LocalRole string

const (
	LocalRoleObserver  LocalRole = "observer"
	LocalRoleOperator  LocalRole = "operator"
	LocalRoleHostAdmin LocalRole = "host-admin"
)

// LocalCredential is one bounded host-local API identity. Token is retained
// only long enough to derive a verifier during server construction.
type LocalCredential struct {
	ID    string
	Role  LocalRole
	Token string
}

type localCredentialVerifier struct {
	id        string
	role      LocalRole
	tokenHash [sha256.Size]byte
}

type localPrincipal struct {
	id   string
	role LocalRole
}

type localPrincipalKey struct{}

var localCredentialIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func buildLocalCredentialVerifiers(credentials []LocalCredential) ([]localCredentialVerifier, error) {
	if len(credentials) == 0 || len(credentials) > 16 {
		return nil, errors.New("executor requires between 1 and 16 local credentials")
	}
	seenIDs := make(map[string]struct{}, len(credentials))
	seenHashes := make(map[[sha256.Size]byte]struct{}, len(credentials))
	verifiers := make([]localCredentialVerifier, 0, len(credentials))
	hostAdmins := 0
	for _, credential := range credentials {
		if !localCredentialIDPattern.MatchString(credential.ID) {
			return nil, errors.New("executor local credential ID is invalid")
		}
		if _, exists := seenIDs[credential.ID]; exists {
			return nil, errors.New("executor local credential IDs must be unique")
		}
		seenIDs[credential.ID] = struct{}{}
		if credential.Role != LocalRoleObserver && credential.Role != LocalRoleOperator && credential.Role != LocalRoleHostAdmin {
			return nil, errors.New("executor local credential role is invalid")
		}
		if credential.Role == LocalRoleHostAdmin {
			hostAdmins++
		}
		if strings.TrimSpace(credential.Token) == "" || len(credential.Token) > 4096 {
			return nil, errors.New("executor local credential token must be non-empty and at most 4096 bytes")
		}
		hash := sha256.Sum256([]byte("Bearer " + credential.Token))
		if _, exists := seenHashes[hash]; exists {
			return nil, errors.New("executor local credential tokens must be unique")
		}
		seenHashes[hash] = struct{}{}
		verifiers = append(verifiers, localCredentialVerifier{
			id: credential.ID, role: credential.Role, tokenHash: hash,
		})
	}
	if hostAdmins != 1 {
		return nil, errors.New("executor requires exactly one host-admin local credential")
	}
	return verifiers, nil
}

func (s *Server) authenticate(authorization string) (localPrincipal, bool) {
	presented := sha256.Sum256([]byte(authorization))
	matched := -1
	for index := range s.localCredentials {
		// Compare every configured verifier even after a match. Credential order
		// therefore does not create an early-return timing oracle.
		if subtle.ConstantTimeCompare(presented[:], s.localCredentials[index].tokenHash[:]) == 1 {
			matched = index
		}
	}
	if matched < 0 {
		return localPrincipal{}, false
	}
	credential := s.localCredentials[matched]
	return localPrincipal{id: credential.id, role: credential.role}, true
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		principal, ok := s.authenticate(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized", "valid executor bearer credential required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), localPrincipalKey{}, principal)))
	})
}

func requireLocalRole(role LocalRole, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := r.Context().Value(localPrincipalKey{}).(localPrincipal)
		if !ok || !localRoleAllows(principal.role, role) {
			writeError(w, http.StatusForbidden, "insufficient_role", "executor credential does not permit this operation")
			return
		}
		next(w, r)
	}
}

func localRoleAllows(actual, required LocalRole) bool {
	level := func(role LocalRole) int {
		switch role {
		case LocalRoleObserver:
			return 1
		case LocalRoleOperator:
			return 2
		case LocalRoleHostAdmin:
			return 3
		default:
			return 0
		}
	}
	return level(actual) >= level(required)
}

type localPrincipalResponse struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	Role          LocalRole `json:"role"`
}

func (s *Server) localPrincipal(w http.ResponseWriter, r *http.Request) {
	principal, ok := r.Context().Value(localPrincipalKey{}).(localPrincipal)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "valid executor bearer credential required")
		return
	}
	writeJSON(w, http.StatusOK, localPrincipalResponse{
		SchemaVersion: "steward.executor-local-principal.v1",
		ID:            principal.id,
		Role:          principal.role,
	})
}
