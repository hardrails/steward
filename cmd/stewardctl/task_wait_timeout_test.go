package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTaskWaitRecoversOnlyExplicitObservationTimeout(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		code     string
		recover  bool
		terminal bool
	}{
		{"observation timeout", 504, "task_observation_timeout", true, false},
		{"terminal recovery timeout", 504, "task_observation_timeout", true, true},
		{"invalid response", 502, "invalid_task_status", false, false},
		{"wrong status", 502, "task_observation_timeout", false, false},
		{"unknown timeout", 504, "unknown_timeout", false, false},
		{"revoked authority", 503, "task_observation_revoked", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTaskRuntimeFixture(t)
			raw := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"completed"}`)
			var observations atomic.Int64
			path := "/v1/tasks/" + fixture.taskDigest + "/permits/" + fixture.permitDigest
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ContentLength != 0 || r.Header.Get("X-Steward-Task-Permit") != "" {
					t.Error("observation acquired submission authority")
				}
				if r.Method == http.MethodGet && r.RequestURI == path {
					if test.terminal {
						writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, terminalTaskRuntimeFields(raw, "completed", false)))
						return
					}
					writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture,
						`"phase":"dispatch","state":"dispatch_accepted","run_id":"run_0123456789abcdef0123456789abcdef"`))
					return
				}
				if r.Method != http.MethodPost || r.RequestURI != path+"/observe" {
					t.Errorf("unexpected call: %s %s", r.Method, r.RequestURI)
					http.Error(w, "unexpected call", 400)
					return
				}
				if observations.Add(1) == 1 {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(test.status)
					_, _ = io.WriteString(w, `{"error":"`+test.code+`","message":"observation failed"}`)
					return
				}
				writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, terminalTaskRuntimeFields(raw, "completed", true)))
			}))
			defer server.Close()
			result := filepath.Join(fixture.cli.directory, "recovered.json")
			var output bytes.Buffer
			err := run(fixture.arguments("wait", server.URL, "-result-out", result, "-wait-timeout", "5s"), &output, &bytes.Buffer{})
			if test.recover {
				if err != nil || observations.Load() != 2 {
					t.Fatalf("error=%v observations=%d", err, observations.Load())
				}
				if saved, err := os.ReadFile(result); err != nil || !bytes.Equal(saved, raw) {
					t.Fatalf("result=%q error=%v", saved, err)
				}
			} else {
				if err == nil || observations.Load() != 1 || output.Len() != 0 {
					t.Fatalf("error=%v observations=%d", err, observations.Load())
				}
				if _, err := os.Stat(result); !os.IsNotExist(err) {
					t.Fatalf("failed observation retained output: %v", err)
				}
			}
		})
	}
}

func TestTaskWaitObservationTimeoutCannotExtendTotalDeadline(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	var observations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture,
				`"phase":"dispatch","state":"dispatch_accepted","run_id":"run_0123456789abcdef0123456789abcdef"`))
			return
		}
		observations.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = io.WriteString(w, `{"error":"task_observation_timeout","message":"retry observation"}`)
	}))
	defer server.Close()
	result := filepath.Join(fixture.cli.directory, "timeout.json")
	err := run(fixture.arguments("wait", server.URL, "-result-out", result, "-wait-timeout", "1s"), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") || observations.Load() != 1 {
		t.Fatalf("error=%v observations=%d", err, observations.Load())
	}
	if _, err := os.Stat(result); !os.IsNotExist(err) {
		t.Fatalf("timeout retained output: %v", err)
	}
}
