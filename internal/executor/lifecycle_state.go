package executor

import (
	"context"
	"time"
)

// dockerLifecycleState is the executor's closed interpretation of Docker's
// open-ended container status string. Only running and the two exact stopped
// states are safe lifecycle conclusions. Every other value remains ambiguous,
// including new statuses introduced by a future Docker release.
type dockerLifecycleState uint8

const (
	dockerLifecycleAmbiguous dockerLifecycleState = iota
	dockerLifecycleRunning
	dockerLifecycleStopped
)

const dockerStopTimeout = 15 * time.Second

func classifyDockerLifecycle(status string) dockerLifecycleState {
	switch status {
	case "running":
		return dockerLifecycleRunning
	case "created", "exited":
		return dockerLifecycleStopped
	default:
		return dockerLifecycleAmbiguous
	}
}

func lifecycleMatches(status string, wantRunning bool) bool {
	state := classifyDockerLifecycle(status)
	if wantRunning {
		return state == dockerLifecycleRunning
	}
	return state == dockerLifecycleStopped
}

// boundedDockerStop prevents a daemon or test backend from holding a lifecycle
// mutation indefinitely. Callers must always reinspect the target afterward;
// the response may be lost after Docker has already applied the stop.
func boundedDockerStop(ctx context.Context, docker Docker, name string) error {
	stopCtx, cancel := context.WithTimeout(ctx, dockerStopTimeout)
	defer cancel()
	return docker.Stop(stopCtx, name)
}
