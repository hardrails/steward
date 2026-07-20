package zfsstorage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

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
}

type dockerVolume struct {
	Name    string            `json:"Name"`
	Driver  string            `json:"Driver"`
	Options map[string]string `json:"Options"`
	Labels  map[string]string `json:"Labels"`
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

func dockerResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
