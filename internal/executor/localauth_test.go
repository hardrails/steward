package executor

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalCredentialRolesEnforceRouteBoundaries(t *testing.T) {
	server, err := NewServerWithLocalCredentials(&fakeDocker{}, []LocalCredential{
		{ID: "node-admin", Role: LocalRoleHostAdmin, Token: "admin-secret"},
		{ID: "automation", Role: LocalRoleOperator, Token: "operator-secret"},
		{ID: "monitoring", Role: LocalRoleObserver, Token: "observer-secret"},
	}, DefaultHostPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, token, method, path, body string
		want                            int
	}{
		{name: "health remains public", method: http.MethodGet, path: "/v1/healthz", want: http.StatusOK},
		{name: "other routes authenticate", method: http.MethodGet, path: "/v1/readiness", want: http.StatusUnauthorized},
		{name: "observer reads readiness", token: "observer-secret", method: http.MethodGet, path: "/v1/readiness", want: http.StatusOK},
		{name: "observer cannot start", token: "observer-secret", method: http.MethodPost, path: "/v1/workloads/stw_invalid/start", want: http.StatusForbidden},
		{name: "operator reaches lifecycle", token: "operator-secret", method: http.MethodPost, path: "/v1/workloads/stw_invalid/start", want: http.StatusBadRequest},
		{name: "operator cannot provision", token: "operator-secret", method: http.MethodPost, path: "/v1/workloads", body: `{}`, want: http.StatusForbidden},
		{name: "operator reaches maintenance", token: "operator-secret", method: http.MethodPost, path: "/v1/maintenance/enter", body: `{}`, want: http.StatusServiceUnavailable},
		{name: "operator cannot purge", token: "operator-secret", method: http.MethodPost, path: "/v1/state/purge", body: `{}`, want: http.StatusForbidden},
		{name: "admin reaches provision", token: "admin-secret", method: http.MethodPost, path: "/v1/workloads", body: `{}`, want: http.StatusBadRequest},
		{name: "admin reaches purge", token: "admin-secret", method: http.MethodPost, path: "/v1/state/purge", body: `{}`, want: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, bytes.NewBufferString(test.body))
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestLocalPrincipalReportsAuthenticatedIdentity(t *testing.T) {
	server, err := NewServerWithLocalCredentials(&fakeDocker{}, []LocalCredential{
		{ID: "node-admin", Role: LocalRoleHostAdmin, Token: "admin-secret"},
		{ID: "monitoring", Role: LocalRoleObserver, Token: "observer-secret"},
	}, DefaultHostPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/local-principal", nil)
	request.Header.Set("Authorization", "Bearer observer-secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "{\"schema_version\":\"steward.executor-local-principal.v1\",\"id\":\"monitoring\",\"role\":\"observer\"}\n" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestLocalCredentialConfigurationFailsClosed(t *testing.T) {
	validAdmin := LocalCredential{ID: "admin", Role: LocalRoleHostAdmin, Token: "admin-secret"}
	tests := []struct {
		name        string
		credentials []LocalCredential
	}{
		{name: "empty"},
		{name: "no admin", credentials: []LocalCredential{{ID: "observer", Role: LocalRoleObserver, Token: "observer-secret"}}},
		{name: "two admins", credentials: []LocalCredential{validAdmin, {ID: "admin-2", Role: LocalRoleHostAdmin, Token: "other-secret"}}},
		{name: "duplicate ID", credentials: []LocalCredential{validAdmin, {ID: "admin", Role: LocalRoleObserver, Token: "other-secret"}}},
		{name: "duplicate token", credentials: []LocalCredential{validAdmin, {ID: "observer", Role: LocalRoleObserver, Token: "admin-secret"}}},
		{name: "unknown role", credentials: []LocalCredential{validAdmin, {ID: "other", Role: "owner", Token: "other-secret"}}},
		{name: "invalid ID", credentials: []LocalCredential{{ID: "bad/id", Role: LocalRoleHostAdmin, Token: "admin-secret"}}},
		{name: "empty token", credentials: []LocalCredential{{ID: "admin", Role: LocalRoleHostAdmin}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewServerWithLocalCredentials(&fakeDocker{}, test.credentials, DefaultHostPolicy(), nil); err == nil {
				t.Fatal("invalid local credential configuration accepted")
			}
		})
	}
}
