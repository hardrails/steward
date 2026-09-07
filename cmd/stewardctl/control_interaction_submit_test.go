package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
)

// These are transport tests, not signature-acceptance tests: the courier must
// preserve even opaque input; Control and Gateway enforce the signed protocol.
func TestControlInteractionSubmitResponsePreservesBytesAndChecksReceipt(t *testing.T) {
	for _, scenario := range []string{"queued", "resolved", "wrong permit", "wrong response", "wrong size", "open", "wrong tenant", "rejected", "uncertain", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			permit := []byte("opaque signed permit\n")
			response := []byte("{\n \"schema_version\":\"steward.interaction-response-body.v1\",\"text\":\"café <&>\"\n}\n")
			now := time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC)
			question := cliInteraction(now)
			receipt := question
			receipt.State = controlstore.InteractionResponseQueued
			receipt.ResponseKeyID = "tenant-task"
			receipt.PermitDigest = dsse.Digest(permit)
			receipt.ResponseDigest = interactionpermit.ResponseDigest(response)
			receipt.ResponseBytes = int64(len(response))
			receipt.ResponseQueuedAt = now.Format(time.RFC3339Nano)
			switch scenario {
			case "resolved":
				receipt.State = controlstore.InteractionResolved
				receipt.ResolvedAt = now.Add(time.Second).Format(time.RFC3339Nano)
			case "wrong permit":
				receipt.PermitDigest = dsse.Digest([]byte("other permit"))
			case "wrong response":
				receipt.ResponseDigest = interactionpermit.ResponseDigest([]byte("other answer"))
			case "wrong size":
				receipt.ResponseBytes++
			case "open":
				receipt = question
			case "wrong tenant":
				receipt.TenantID = "other-tenant"
				refreshCLIInteractionDigest(&receipt)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/v1/tenants/tenant-a/interactions/"+question.InteractionID+"/response" ||
					r.Header.Get("Authorization") != "Bearer operator" {
					t.Errorf("unexpected courier method, route, or authorization")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				var courier struct {
					Permit   string `json:"permit_base64"`
					Response string `json:"response_base64"`
				}
				if err := json.NewDecoder(r.Body).Decode(&courier); err != nil {
					t.Error(err)
				}
				if courier.Permit != base64.StdEncoding.EncodeToString(permit) || courier.Response != base64.StdEncoding.EncodeToString(response) {
					t.Error("courier changed signed bytes")
				}
				w.Header().Set("Content-Type", "application/json")
				switch scenario {
				case "rejected":
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":"response_conflict","message":"retained answer differs"}`))
				case "uncertain":
					w.WriteHeader(http.StatusAccepted)
					_, _ = w.Write([]byte(`{"incomplete":`))
				case "redirect":
					w.Header().Set("Location", "/unexpected")
					w.WriteHeader(http.StatusTemporaryRedirect)
				default:
					w.WriteHeader(http.StatusAccepted)
					_ = json.NewEncoder(w).Encode(receipt)
				}
			}))
			defer server.Close()
			args := courierArguments(t, server.URL, question.InteractionID, permit, response)
			var output bytes.Buffer
			err := controlCommand(append([]string{"interaction", "submit-response", "-no-context"}, args...), &output)
			wantSuccess := scenario == "queued" || scenario == "resolved"
			if (err == nil) != wantSuccess || calls.Load() != 1 {
				t.Fatalf("err=%v calls=%d wantSuccess=%v", err, calls.Load(), wantSuccess)
			}
			if wantSuccess {
				var got controlstore.Interaction
				if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.State != receipt.State || got.ResponseDigest != receipt.ResponseDigest {
					t.Fatalf("incorrect receipt: %v", err)
				}
			} else if output.Len() != 0 {
				t.Fatal("failed submission printed a success receipt")
			}
		})
	}
}

func courierArguments(t *testing.T, origin, interactionID string, permit, response []byte) []string {
	t.Helper()
	dir := t.TempDir()
	for name, raw := range map[string][]byte{"operator.token": []byte("operator\n"), "permit": permit, "response": response} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"-tenant-id", "tenant-a", "-interaction-id", interactionID, "-control-url", origin,
		"-token-file", filepath.Join(dir, "operator.token"), "-permit-file", filepath.Join(dir, "permit"), "-response-file", filepath.Join(dir, "response")}
}

func TestControlInteractionSubmitResponseRejectsUnsafeFilesBeforeNetwork(t *testing.T) {
	for _, target := range []string{"-permit-file", "-response-file"} {
		for _, scenario := range []string{"empty", "oversize", "readable", "symlink", "missing", "directory"} {
			t.Run(target+"/"+scenario, func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
				}))
				defer server.Close()
				args := courierArguments(t, server.URL, cliInteraction(time.Now()).InteractionID, []byte("permit"), []byte("response"))
				for i := 0; i < len(args); i += 2 {
					if args[i] != target {
						continue
					}
					path := args[i+1]
					var err error
					switch scenario {
					case "empty":
						err = os.Truncate(path, 0)
					case "oversize":
						limit := int64(interactionpermit.MaxEnvelopeBytes)
						if target == "-response-file" {
							limit = interactionpermit.MaxResponseBytes
						}
						err = os.Truncate(path, limit+1)
					case "readable":
						err = os.Chmod(path, 0o644)
					case "symlink":
						args[i+1] = path + ".link"
						err = os.Symlink(path, args[i+1])
					case "missing":
						args[i+1] = path + ".missing"
					case "directory":
						args[i+1] = filepath.Dir(path)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				var output bytes.Buffer
				if err := controlInteractionSubmitResponse(args, &output); err == nil || calls.Load() != 0 || output.Len() != 0 {
					t.Fatalf("unsafe input: err=%v calls=%d", err, calls.Load())
				}
			})
		}
	}
}

func TestControlInteractionSubmitResponseRejectsSigningFlags(t *testing.T) {
	for _, args := range [][]string{nil, {"-key", "private.pem"}, {"-key-id", "task-key"}, {"unexpected"}} {
		if err := controlInteractionSubmitResponse(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid arguments: %v", args)
		}
	}
	policy, exists := controlContextCommands["interaction submit-response"]
	if !exists || !policy.network || !policy.token || !policy.tenant || policy.taskKey {
		t.Fatal("courier context must supply transport credentials, never a signing key")
	}
}
