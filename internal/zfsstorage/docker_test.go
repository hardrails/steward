package zfsstorage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDockerMigrationCheckUsesUnixSocketAndRefusesRedirects(t *testing.T) {
	// Keep the socket below the portable Unix path-length limit, including on macOS.
	directory, err := os.MkdirTemp("/tmp", "steward-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path != "/v1.41/containers/json" {
			t.Error("Docker redirect was followed")
		}
		if request.URL.Query().Get("filters") == `{"volume":["steward-redirect"]}` {
			http.Redirect(response, request, "/forbidden", http.StatusTemporaryRedirect)
			return
		}
		_, _ = io.WriteString(response, "[]")
	}))
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	binder, err := NewDockerBinder(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(binder.client.CloseIdleConnections)
	if err := binder.CheckUnused(context.Background(), "steward-retained"); err != nil {
		t.Fatal(err)
	}
	if err := binder.CheckUnused(context.Background(), "steward-redirect"); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect error=%v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("unexpected Docker requests: %d", calls.Load())
	}
	server.Close()
	if err := binder.CheckUnused(context.Background(), "steward-retained"); err == nil {
		t.Fatal("offline Docker socket accepted as proof of no references")
	}
}

func TestDockerMigrationReferenceCheckIncludesStoppedContainersAndFailsClosed(t *testing.T) {
	for _, response := range []string{"[]", "[ ]", `[{"State":"running"}]`, `[{"State":"exited"}]`, "null", "{}", "invalid", strings.Repeat(" ", maxDockerResponseBytes+1)} {
		t.Run(response[:min(len(response), 40)], func(t *testing.T) {
			binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				var filters map[string][]string
				if request.Method != http.MethodGet || request.URL.Path != "/v1.41/containers/json" || request.URL.Query().Get("all") != "1" ||
					json.Unmarshal([]byte(request.URL.Query().Get("filters")), &filters) != nil || len(filters["volume"]) != 1 || filters["volume"][0] != "steward-retained" {
					t.Fatalf("unsafe Docker query: %s", request.URL)
				}
				return dockerResponse(http.StatusOK, response), nil
			})})
			err := binder.CheckUnused(context.Background(), "steward-retained")
			if (err == nil) != (response == "[]" || response == "[ ]") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return dockerResponse(http.StatusServiceUnavailable, "[]"), nil
	})})
	if err := binder.CheckUnused(context.Background(), "steward-retained"); err == nil {
		t.Fatal("failed Docker request accepted")
	}
	if err := binder.CheckUnused(context.Background(), "../escape"); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("invalid handle accepted: %v", err)
	}
}

func TestDockerBinderExactLifecycle(t *testing.T) {
	engine := &fakeDockerVolumes{volumes: make(map[string]dockerVolume)}
	binder := newDockerBinder(&http.Client{Transport: engine})
	binding := Binding{Handle: "steward-zfs-abc", Source: "/var/lib/steward/v-abc", Labels: map[string]string{
		"io.hardrails.steward.managed": "true", "io.hardrails.steward.backend-ref": "zfs-volume-abc",
	}}
	changed, err := binder.Ensure(context.Background(), binding)
	if err != nil || !changed {
		observed, inspectErr := binder.Inspect(context.Background(), binding.Handle)
		t.Fatalf("ensure = (%v, %v), stored=%+v inspect=(%+v, %v)", changed, err, engine.volumes, observed, inspectErr)
	}
	changed, err = binder.Ensure(context.Background(), binding)
	if err != nil || changed {
		t.Fatalf("replay ensure = (%v, %v)", changed, err)
	}
	observed, err := binder.Inspect(context.Background(), binding.Handle)
	if err != nil || !sameBinding(observed, binding) {
		t.Fatalf("inspect = (%+v, %v)", observed, err)
	}
	engine.volumes[binding.Handle] = dockerVolume{Name: binding.Handle, Driver: "local", Options: map[string]string{
		"type": "none", "o": "bind", "device": "/attacker",
	}, Labels: cloneStringMap(binding.Labels)}
	if _, err := binder.Ensure(context.Background(), binding); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("rebound ensure error = %v, want conflict", err)
	}
	engine.volumes[binding.Handle] = dockerVolume{Name: binding.Handle, Driver: "local", Options: map[string]string{
		"type": "none", "o": "bind", "device": binding.Source,
	}, Labels: cloneStringMap(binding.Labels)}
	changed, err = binder.Delete(context.Background(), binding.Handle)
	if err != nil || !changed {
		t.Fatalf("delete = (%v, %v)", changed, err)
	}
	changed, err = binder.Delete(context.Background(), binding.Handle)
	if !errors.Is(err, ErrBindingNotFound) || changed {
		t.Fatalf("replay delete = (%v, %v)", changed, err)
	}
}

func TestDockerBinderRejectsHostileInputsAndResponses(t *testing.T) {
	for _, socket := range []string{"", "relative.sock", "/", "/tmp/../docker.sock"} {
		if _, err := NewDockerBinder(socket); err == nil {
			t.Fatalf("unsafe socket accepted: %q", socket)
		}
	}
	binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxDockerResponseBytes+1)))}, nil
	})})
	if _, err := binder.Inspect(context.Background(), "steward-safe"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response error = %v", err)
	}
	if _, err := binder.Inspect(context.Background(), "../escape"); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("hostile handle error = %v, want conflict", err)
	}
	if _, _, err := (*DockerBinder)(nil).call(context.Background(), http.MethodGet, "/", nil); err == nil {
		t.Fatal("nil Docker binder was callable")
	}
	if dockerStatusError(http.StatusTeapot).Error() == "" {
		t.Fatal("Docker status error was empty")
	}
}

func TestDockerBinderFailsClosedOnMalformedDaemonState(t *testing.T) {
	for name, response := range map[string]*http.Response{
		"server status": dockerResponse(http.StatusInternalServerError, `{}`),
		"invalid json":  dockerResponse(http.StatusOK, `{`),
		"wrong driver":  dockerResponse(http.StatusOK, `{"Name":"steward-safe","Driver":"other","Options":{},"Labels":{}}`),
		"bad options":   dockerResponse(http.StatusOK, `{"Name":"steward-safe","Driver":"local","Options":{"type":"none"},"Labels":{}}`),
		"bad labels":    dockerResponse(http.StatusOK, `{"Name":"steward-safe","Driver":"local","Options":{"type":"none","o":"bind","device":"/state"},"Labels":[]}`),
		"wrong name":    dockerResponse(http.StatusOK, `{"Name":"steward-other","Driver":"local","Options":{"type":"none","o":"bind","device":"/state"},"Labels":{"managed":"true","ref":"one"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response, nil
			})})
			if _, err := binder.Inspect(context.Background(), "steward-safe"); err == nil {
				t.Fatal("malformed Docker response was accepted")
			}
		})
	}
	for status, want := range map[int]error{
		http.StatusConflict: ErrBindingInUse,
		http.StatusNotFound: ErrBindingNotFound,
	} {
		binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return dockerResponse(status, `{}`), nil
		})})
		if _, err := binder.Delete(context.Background(), "steward-safe"); !errors.Is(err, want) {
			t.Fatalf("delete HTTP %d error = %v", status, err)
		}
	}
	if _, err := decodeStringMap(nil, 1); err == nil {
		t.Fatal("empty string map was decoded")
	}
	if _, err := decodeStringMap([]byte(`{"a":"b","c":"d"}`), 1); err == nil {
		t.Fatal("oversized string map was decoded")
	}
	if err := validateBinding(Binding{Handle: "valid", Source: "/state", Labels: map[string]string{"": "x", "ref": "y"}}); err == nil {
		t.Fatal("empty Docker label key was accepted")
	}
	binding := Binding{Handle: "steward-safe", Source: "/state", Labels: map[string]string{"managed": "true", "ref": "one"}}
	binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return dockerResponse(http.StatusNotFound, `{}`), nil
		}
		return dockerResponse(http.StatusOK, `{}`), nil
	})})
	if _, err := binder.Ensure(context.Background(), binding); err == nil || !strings.Contains(err.Error(), "HTTP 200") {
		t.Fatalf("unexpected Docker create status error = %v", err)
	}
	binder = newDockerBinder(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return dockerResponse(http.StatusTeapot, `{}`), nil
	})})
	if _, err := binder.Delete(context.Background(), binding.Handle); err == nil || !strings.Contains(err.Error(), "HTTP 418") {
		t.Fatalf("unexpected Docker delete status error = %v", err)
	}
}

type dockerVolume struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	Scope      string            `json:"Scope"`
	Options    map[string]string `json:"Options"`
	Labels     map[string]string `json:"Labels"`
}

type fakeDockerVolumes struct{ volumes map[string]dockerVolume }

func (engine *fakeDockerVolumes) RoundTrip(request *http.Request) (*http.Response, error) {
	path := strings.TrimPrefix(request.URL.Path, "/v1.41/volumes/")
	switch {
	case request.Method == http.MethodGet:
		volume, ok := engine.volumes[path]
		if !ok {
			return dockerResponse(http.StatusNotFound, `{}`), nil
		}
		volume.Mountpoint = "/var/lib/docker/volumes/" + volume.Name + "/_data"
		volume.Scope = "local"
		raw, _ := json.Marshal(volume)
		return dockerResponse(http.StatusOK, string(raw)), nil
	case request.Method == http.MethodPost && request.URL.Path == "/v1.41/volumes/create":
		raw, _ := io.ReadAll(request.Body)
		var input struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			DriverOpts map[string]string `json:"DriverOpts"`
			Labels     map[string]string `json:"Labels"`
		}
		if err := json.Unmarshal(raw, &input); err != nil {
			return dockerResponse(http.StatusBadRequest, `{}`), nil
		}
		if _, exists := engine.volumes[input.Name]; !exists {
			engine.volumes[input.Name] = dockerVolume{Name: input.Name, Driver: input.Driver, Options: input.DriverOpts, Labels: input.Labels}
		}
		return dockerResponse(http.StatusCreated, `{}`), nil
	case request.Method == http.MethodDelete:
		if _, ok := engine.volumes[path]; !ok {
			return dockerResponse(http.StatusNotFound, `{}`), nil
		}
		delete(engine.volumes, path)
		return dockerResponse(http.StatusNoContent, ""), nil
	default:
		return dockerResponse(http.StatusNotFound, `{}`), nil
	}
}

func TestDockerBinderAcceptsEngine141VolumeMetadata(t *testing.T) {
	// Shape captured from a real Engine v1.41 volume inspect, not a reduced
	// fixture. Docker's mountpoint is observational; Options.device is the bind.
	const body = `{"CreatedAt":"2026-09-09T04:53:10Z","Driver":"local","Labels":{"io.hardrails.steward.backend-ref":"zfs-volume-probe","io.hardrails.steward.managed":"true"},"Mountpoint":"/var/lib/docker/volumes/steward-probe/_data","Name":"steward-probe","Options":{"device":"/var/lib/steward-state/probe","o":"bind","type":"none"},"Scope":"local"}`
	for _, suffix := range []string{"", `,"Status":{"driver":{"ready":true}},"UsageData":{"Size":-1,"RefCount":0}`} {
		binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return dockerResponse(http.StatusOK, strings.TrimSuffix(body, "}")+suffix+"}"), nil
		})})
		got, err := binder.Inspect(context.Background(), "steward-probe")
		if err != nil || got.Source != "/var/lib/steward-state/probe" || got.Handle != "steward-probe" {
			t.Fatalf("real Engine response = (%+v, %v)", got, err)
		}
	}
	for name, changed := range map[string]string{
		"duplicate identity":    strings.TrimSuffix(body, "}") + `,"Name":"steward-probe"}`,
		"unknown field":         strings.TrimSuffix(body, "}") + `,"unexpected":true}`,
		"global scope":          strings.Replace(body, `"Scope":"local"`, `"Scope":"global"`, 1),
		"missing scope":         strings.Replace(body, `,"Scope":"local"`, "", 1),
		"wrong mountpoint type": strings.Replace(body, `"/var/lib/docker/volumes/steward-probe/_data"`, "[]", 1),
		"relative mountpoint":   strings.Replace(body, `"/var/lib/docker/volumes/steward-probe/_data"`, `"relative"`, 1),
		"wrong options":         strings.Replace(body, `"o":"bind"`, `"o":"rbind"`, 1),
		"wrong name":            strings.Replace(body, `"Name":"steward-probe"`, `"Name":"steward-other"`, 1),
		"invalid labels":        strings.Replace(body, `"io.hardrails.steward.managed":"true"`, `"io.hardrails.steward.managed":[]`, 1),
		"empty label key":       strings.Replace(body, `"io.hardrails.steward.managed":"true"`, `"":"true"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return dockerResponse(http.StatusOK, changed), nil
			})})
			if _, err := binder.Inspect(context.Background(), "steward-probe"); !errors.Is(err, ErrBindingConflict) {
				t.Fatalf("malformed Engine response: %v", err)
			}
		})
	}
}

func TestDockerMutationDoesNotClaimSuccessAfterTransportOrVerificationFailure(t *testing.T) {
	binding := Binding{Handle: "steward-safe", Source: "/state", Labels: map[string]string{"managed": "true", "ref": "one"}}
	for _, phase := range []string{"inspect", "create", "verify", "rebound", "delete"} {
		t.Run(phase, func(t *testing.T) {
			engine := &fakeDockerVolumes{volumes: make(map[string]dockerVolume)}
			failure := errors.New("Docker connection lost")
			created := false
			binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if phase == "delete" || phase == "inspect" ||
					phase == "create" && request.Method == http.MethodPost ||
					phase == "verify" && created {
					return nil, failure
				}
				response, err := engine.RoundTrip(request)
				if request.Method == http.MethodPost && err == nil {
					created = true
					if phase == "rebound" {
						volume := engine.volumes[binding.Handle]
						volume.Options["device"] = "/other"
						engine.volumes[binding.Handle] = volume
					}
				}
				return response, err
			})})
			var changed bool
			var err error
			if phase == "delete" {
				changed, err = binder.Delete(context.Background(), binding.Handle)
			} else {
				changed, err = binder.Ensure(context.Background(), binding)
			}
			want := failure
			if phase == "rebound" {
				want = ErrBindingConflict
			}
			if changed || !errors.Is(err, want) {
				t.Fatalf("mutation claimed success or lost boundary: changed=%v, error=%v", changed, err)
			}
			if (phase == "verify" || phase == "rebound") && !created {
				t.Fatal("verification failure did not follow creation")
			}
		})
	}
}

func dockerResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
