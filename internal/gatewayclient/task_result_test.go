package gatewayclient

import "testing"

func TestTaskResultPresenceIncludesEveryDurableOutcomeField(t *testing.T) {
	if hasTaskResult(TaskLifecycleStatus{}) {
		t.Fatal("empty task lifecycle status reported a result")
	}
	for name, status := range map[string]TaskLifecycleStatus{
		"run":          {RunID: "run-1"},
		"task status":  {TaskStatus: "completed"},
		"digest":       {ResultDigest: "sha256:value"},
		"bytes":        {ResponseBytes: 1},
		"error":        {ErrorCode: "failed"},
		"retry safety": {RetrySafety: "unsafe"},
		"observed":     {ObservedStatus: ObservedCompleted},
		"raw receipt":  {ObservationBase64: "e30="},
	} {
		t.Run(name, func(t *testing.T) {
			if !hasTaskResult(status) {
				t.Fatal("durable task result field was ignored")
			}
		})
	}
}
