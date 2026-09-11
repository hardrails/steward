package gateway

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
)

func TestScopedInferenceMainAndAuxiliaryCallsRespectRouteCapacity(t *testing.T) {
	for _, capacity := range []int{2, 4} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			entered := make(chan struct{}, capacity)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var calls atomic.Int64
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				entered <- struct{}{}
				select {
				case <-release:
					_, _ = w.Write([]byte(`{"choices":[]}`))
				case <-r.Context().Done():
				}
			}))
			defer provider.Close()
			defer unblock()
			var admitted atomic.Int64
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_, _ = fmt.Fprintf(w, `{"run_id":"run-%d"}`, admitted.Add(1))
			}))
			defer service.Close()
			rig, route := taskScopedInferenceRig(t, service.URL, provider)
			route.MaxConcurrent = capacity
			rig.server.routes[route.ID] = route
			rig.server.config.Routes = []Route{route.Route}
			rig.server.semaphores[route.ID] = make(chan struct{}, capacity)
			rig.server.policyDigests[rig.grant.GrantID] = rig.server.routePolicyDigestLocked(rig.grant)
			permits := make([]string, 2)
			for i := range permits {
				body := []byte(fmt.Sprintf(`{"input":"task-%d"}`, i))
				permits[i] = taskPermitFor(t, rig, fmt.Sprintf("task-%d", i), body, nil)
				if result := invokeServiceTask(rig, body, permits[i]); result.Code != http.StatusAccepted {
					t.Fatalf("task admission failed: %d", result.Code)
				}
			}
			// Exercise the full HTTP handler, not proxyInference directly: the
			// route semaphore lives outside the task-scoped proxy and ledger.
			gateway := httptest.NewServer(rig.server.inferenceHandler(rig.grant.GrantID))
			defer gateway.Close()
			defer unblock()
			client := gateway.Client()
			client.Timeout = 10 * time.Second
			request := func(permit string) (int, error) {
				r, err := http.NewRequest(http.MethodPost, gateway.URL+"/v1/chat/completions", strings.NewReader(`{"model":"default"}`))
				if err != nil {
					return 0, err
				}
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", "Bearer "+permit)
				response, err := client.Do(r)
				if err != nil {
					return 0, err
				}
				defer response.Body.Close()
				_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
				return response.StatusCode, err
			}
			finished := make(chan int, capacity)
			for i := 0; i < capacity; i++ {
				go func() {
					status, err := request(permits[i%2])
					if err != nil {
						status = 0
					}
					finished <- status
				}()
			}
			for i := 0; i < capacity; i++ {
				select {
				case <-entered:
				case <-time.After(10 * time.Second):
					t.Fatal("the configured parallel calls did not all reach the provider")
				}
			}
			// Two held main calls starve an auxiliary call at capacity two.
			// Four slots admit two main plus two auxiliary calls, but not five.
			if status, err := request(permits[0]); err != nil || status != http.StatusTooManyRequests {
				t.Fatalf("excess call status=%d error=%v", status, err)
			}
			if calls.Load() != int64(capacity) {
				t.Fatal("the rejected request reached the provider")
			}
			unblock()
			for i := 0; i < capacity; i++ {
				if status := <-finished; status != http.StatusOK {
					t.Fatalf("accepted call status=%d", status)
				}
			}
			byTask := map[string]int{}
			public := rig.config.connectorReceiptKey.Public().(ed25519.PublicKey)
			_, err := connectorledger.VerifyRecords(rig.config.ConnectorReceiptFile, public,
				rig.config.ConnectorReceiptNodeID, 1, func(record connectorledger.VerifiedReceipt) error {
					if event := record.Receipt.Event; event.Kind == connectorledger.InferenceAttempt {
						byTask[event.InferenceTaskDigest]++
					}
					return nil
				})
			if err != nil || len(byTask) != 2 {
				t.Fatalf("task-scoped ledger verification failed: %v", err)
			}
			for _, count := range byTask {
				if count != capacity {
					t.Fatalf("task has %d events, expected %d; rejected calls must add none", count, capacity)
				}
			}
		})
	}
}
