package executor

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestDockerNetworkAllocationIntegration(t *testing.T) {
	socket := os.Getenv("STEWARD_DOCKER_INTEGRATION_SOCKET")
	if socket == "" {
		t.Skip("set STEWARD_DOCKER_INTEGRATION_SOCKET to run against a disposable Docker daemon")
	}
	image := os.Getenv("STEWARD_DOCKER_INTEGRATION_IMAGE")
	if image == "" {
		image = "alpine:3.20"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docker := NewDockerHTTPWithTimeout(socket, 20*time.Second)
	spec := NetworkSpecFor("integration", "docker-static-ip", uint64(time.Now().UnixNano()))
	_ = docker.RemoveNetwork(ctx, spec.Name)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = docker.RemoveNetwork(cleanupCtx, spec.Name)
	})
	if err := docker.CreateNetwork(ctx, spec); err != nil {
		t.Fatal(err)
	}
	observed, err := docker.InspectNetwork(ctx, spec.Name)
	if err != nil || !explicitNetworkEqual(observed, spec) {
		t.Fatalf("explicit Docker network=%#v err=%v", observed, err)
	}
	for name, address := range map[string]string{
		"steward-ipam-integration-relay": observed.RelayIP,
		"steward-ipam-integration-agent": observed.AgentIP,
	} {
		name += "-" + observed.Name[len("steward-net-"):25]
		body := map[string]any{
			"Image": image,
			"Cmd":   []string{"true"},
			"HostConfig": map[string]any{
				"NetworkMode": observed.Name,
			},
			"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{
				observed.Name: map[string]any{
					"IPAMConfig": map[string]string{"IPv4Address": address},
				},
			}},
		}
		if err := docker.call(
			ctx, http.MethodPost, "/v1.41/containers/create?name="+url.QueryEscape(name),
			body, http.StatusCreated,
		); err != nil {
			t.Fatalf("create static endpoint %s: %v", address, err)
		}
		endpointName := name
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			err := docker.call(
				cleanupCtx, http.MethodDelete, "/v1.41/containers/"+pathEscape(endpointName)+"?force=1",
				nil, http.StatusNoContent,
			)
			if err != nil && !errors.Is(err, ErrNotFound) {
				t.Errorf("remove integration endpoint %s: %v", endpointName, err)
			}
		})
	}
}
