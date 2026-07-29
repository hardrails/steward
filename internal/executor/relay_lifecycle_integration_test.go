package executor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDockerRelayLifecycleIntegration(t *testing.T) {
	image := os.Getenv("STEWARD_RELAY_INTEGRATION_IMAGE")
	socket := os.Getenv("STEWARD_RELAY_INTEGRATION_SOCKET")
	if image == "" || socket == "" {
		t.Skip("set STEWARD_RELAY_INTEGRATION_IMAGE and STEWARD_RELAY_INTEGRATION_SOCKET to run")
	}
	grantDir := os.Getenv("STEWARD_RELAY_INTEGRATION_GRANT_DIR")
	if grantDir == "" {
		grantDir = t.TempDir()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docker := NewDockerHTTPWithTimeout(socket, 20*time.Second)
	identity := NetworkSpecFor("integration", "relay-lifecycle", uint64(time.Now().UnixNano()))
	relayName := RelayName(identity.TenantID, identity.InstanceID, identity.Generation)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = docker.Remove(cleanupCtx, relayName)
		_ = docker.RemoveNetwork(cleanupCtx, identity.Name)
	})
	if err := docker.CreateNetwork(ctx, identity); err != nil {
		t.Fatal(err)
	}
	network, err := docker.InspectNetwork(ctx, identity.Name)
	if err != nil {
		t.Fatal(err)
	}
	spec := RelaySpec{
		Name: relayName, Image: image, NetworkName: network.Name,
		GrantID: "grant-" + strings.Repeat("a", 64), GrantDir: grantDir,
		TenantID: network.TenantID, InstanceID: network.InstanceID, Generation: network.Generation,
		RelayGID: 1234, Inference: true, RelayIP: network.RelayIP, AgentIP: network.AgentIP,
		MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32,
	}
	if err := docker.CreateRelay(ctx, spec); err != nil {
		t.Fatal(err)
	}
	created, err := docker.InspectRelay(ctx, relayName)
	if err != nil || !relayEqual(created, spec) {
		t.Fatalf("created relay=%#v want=%#v err=%v", created, spec, err)
	}
	if err := docker.Start(ctx, relayName); err != nil {
		t.Fatal(err)
	}
	running, err := docker.InspectRelay(ctx, relayName)
	if err != nil || !relayEqual(running, spec) {
		t.Fatalf("running relay=%#v want=%#v err=%v", running, spec, err)
	}
}
