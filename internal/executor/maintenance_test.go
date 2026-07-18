package executor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardrails/steward/internal/admission"
)

func TestMaintenanceCordonsAdmissionAndStartButAllowsContainment(t *testing.T) {
	docker := &secureDocker{}
	server, err := NewServer(docker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	capsule, intent, config := secureAdmissionFixtureFor(t, admission.Capabilities{})
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	if response := submitSecureAdmission(t, server, capsule, intent); response.Code != http.StatusCreated {
		t.Fatalf("initial admission status=%d body=%s", response.Code, response.Body.String())
	}
	runtimeRef := RuntimeRef(intent.TenantID, intent.InstanceID)

	entered := maintenanceRequest(t, server, http.MethodPost, "/v1/maintenance/enter", []byte(`{"reason":"planned kernel maintenance"}`))
	if entered.Code != http.StatusOK {
		t.Fatalf("enter status=%d body=%s", entered.Code, entered.Body.String())
	}
	var status maintenanceStatusResponse
	if err := json.Unmarshal(entered.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Enabled || status.Reason != "planned kernel maintenance" || status.EnteredAt == "" ||
		len(status.ActiveRuntimeRefs) != 1 || status.ActiveRuntimeRefs[0] != runtimeRef {
		t.Fatalf("maintenance status=%+v", status)
	}

	if response := submitSecureAdmission(t, server, capsule, intent); response.Code != http.StatusOK {
		t.Fatalf("exact admission replay status=%d body=%s", response.Code, response.Body.String())
	}
	freshDocker := &secureDocker{}
	fresh, err := NewServer(freshDocker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	freshCapsule, freshIntent, freshConfig := secureAdmissionFixtureFor(t, admission.Capabilities{})
	if err := fresh.EnableSecureAdmission(freshConfig); err != nil {
		t.Fatal(err)
	}
	if response := maintenanceRequest(t, fresh, http.MethodPost, "/v1/maintenance/enter", []byte(`{"reason":"planned kernel maintenance"}`)); response.Code != http.StatusOK {
		t.Fatalf("fresh enter status=%d body=%s", response.Code, response.Body.String())
	}
	if response := submitSecureAdmission(t, fresh, freshCapsule, freshIntent); response.Code != http.StatusServiceUnavailable ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"error":"maintenance_enabled"`)) {
		t.Fatalf("new admission status=%d body=%s", response.Code, response.Body.String())
	}
	if response := maintenanceRequest(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", nil); response.Code != http.StatusServiceUnavailable ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"error":"maintenance_enabled"`)) {
		t.Fatalf("start status=%d body=%s", response.Code, response.Body.String())
	}
	if response := maintenanceRequest(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/stop", nil); response.Code != http.StatusOK {
		t.Fatalf("stop status=%d body=%s", response.Code, response.Body.String())
	}

	conflict := maintenanceRequest(t, server, http.MethodPost, "/v1/maintenance/enter", []byte(`{"reason":"different work"}`))
	if conflict.Code != http.StatusConflict || !bytes.Contains(conflict.Body.Bytes(), []byte(`"error":"maintenance_conflict"`)) {
		t.Fatalf("conflicting enter status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	if response := maintenanceRequest(t, server, http.MethodPost, "/v1/maintenance/exit", nil); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreconciled exit status=%d body=%s", response.Code, response.Body.String())
	}
	server.reconcileMu.Lock()
	server.reconcileAttempted = true
	server.reconcileReport = ReconcileReport{Ready: true}
	server.reconcileMu.Unlock()
	exited := maintenanceRequest(t, server, http.MethodPost, "/v1/maintenance/exit", nil)
	if exited.Code != http.StatusOK {
		t.Fatalf("exit status=%d body=%s", exited.Code, exited.Body.String())
	}
	status = maintenanceStatusResponse{}
	if err := json.Unmarshal(exited.Body.Bytes(), &status); err != nil || status.Enabled || status.EnteredAt != "" || status.Reason != "" {
		t.Fatalf("exited status=%+v error=%v", status, err)
	}
	if response := maintenanceRequest(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", nil); response.Code != http.StatusOK {
		t.Fatalf("start after exit status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMaintenanceAPIIsAuthenticatedBoundedAndSecureOnly(t *testing.T) {
	legacy, err := NewServer(&secureDocker{}, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response := maintenanceRequest(t, legacy, http.MethodGet, "/v1/maintenance", nil); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("legacy status=%d body=%s", response.Code, response.Body.String())
	}
	server := mustSecureServer(t)
	if response := maintenanceRequest(t, server, http.MethodGet, "/v1/maintenance", nil); response.Code != http.StatusOK ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"schema_version":"steward.executor-maintenance.v1"`)) {
		t.Fatalf("secure status=%d body=%s", response.Code, response.Body.String())
	}
	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/maintenance", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	for _, body := range [][]byte{
		[]byte(`{"reason":""}`),
		[]byte(`{"reason":" padded "}`),
		[]byte(`{"reason":"\u007f"}`),
		[]byte(`{"reason":"ok","extra":true}`),
		bytes.Repeat([]byte("x"), maxBodyBytes+1),
	} {
		response := maintenanceRequest(t, server, http.MethodPost, "/v1/maintenance/enter", body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid enter status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if response := maintenanceRequest(t, server, http.MethodPost, "/v1/maintenance/exit", []byte(`{}`)); response.Code != http.StatusBadRequest {
		t.Fatalf("exit body status=%d body=%s", response.Code, response.Body.String())
	}
}

func maintenanceRequest(t *testing.T, server *Server, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}
