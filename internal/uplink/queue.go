package uplink

import (
	"context"
	"strings"
	"sync"
)

// DefaultCommandQueueDepth is the command queue's depth when Config.CommandQueueDepth
// is unset (<= 0). It bounds how many received-but-not-yet-executed commands the poll
// loop holds at once (queued plus in-flight), so a burst from the control plane cannot
// commit the node to unbounded work. cmd/steward always supplies an explicit,
// operator-validated value (see prepareRuntime); this default only serves a library
// caller that constructs a Poller without one. 256 is comfortably above a normal
// reconciliation batch yet a hard ceiling on a pathological burst.
const DefaultCommandQueueDepth = 256

// commandQueue is a bounded, deduplicating FIFO of commands awaiting execution. It
// decouples the poll loop (the producer, which calls enqueue) from command execution
// (the consumer, which calls waitForWork/drain/complete), so two independent
// properties hold that a straight "execute every polled command inline" loop cannot
// give:
//
//   - Backpressure. At most depth commands are ever queued-plus-in-flight. A poll
//     cycle whose commands would exceed the cap has its excess rejected — returned to
//     the caller to log, and left for the control plane to redeliver next cycle —
//     rather than committing the node to unbounded queued or in-flight work.
//   - Deduplication across poll cycles. A command whose command_id is already queued
//     or in-flight is skipped rather than queued a second time, so a command
//     redelivered while its first copy is still pending (a report lost in transit, a
//     claim-lease reclaim) is not executed twice. The tracker's operations are
//     idempotent in effect regardless, so this is a work-saving guard, not a
//     correctness fix — but re-executing a superseded command wastes tracker
//     mutations and (with -state-file) disk writes for no benefit.
//
// It is safe for one producer goroutine and one consumer goroutine (the poll loop and
// its consumer respectively — see Poller.Run); every field access is under mu except
// the wake channel, which carries a single coalesced "work available" signal.
type commandQueue struct {
	depth int

	mu    sync.Mutex
	items []command // queued, not yet drained, in FIFO order.
	// inflight is the set of command_ids currently queued OR being executed, for
	// the cross-cycle dedup guard. It holds only non-empty command_ids: an empty id
	// is out-of-contract for the control plane, and collapsing every empty-id command
	// onto one map key would wrongly treat distinct commands as duplicates, so an
	// empty-id command is never deduplicated (it still counts toward capacity via
	// outstanding).
	inflight map[string]struct{}
	// outstanding is the queued-plus-in-flight count the depth cap bounds. It counts
	// empty-id commands too (which inflight cannot), so it — not len(inflight) — is
	// the authoritative capacity measure and the /metrics gauge source.
	outstanding int

	// wake carries a single coalesced signal that work may be available. It is
	// buffered (size 1) and sent non-blocking, so a burst of enqueues never blocks the
	// producer and never loses a wake: whenever items is non-empty, either a wake is
	// buffered or the consumer is between drain and its next waitForWork and will
	// re-check. A spurious wake (drain finds nothing) is handled by the consumer, not
	// an error.
	wake chan struct{}
}

// newCommandQueue builds an empty queue bounded at depth. depth is assumed positive
// (NewPoller substitutes DefaultCommandQueueDepth for a non-positive Config value, and
// cmd/steward rejects a non-positive operator value fail-closed before ever reaching
// here).
func newCommandQueue(depth int) *commandQueue {
	return &commandQueue{
		depth:    depth,
		inflight: make(map[string]struct{}),
		wake:     make(chan struct{}, 1),
	}
}

// enqueue admits as many of cmds as fit under the depth cap, in order, and returns the
// commands it did not admit so the caller can log them and let the control plane
// redeliver them:
//
//   - rejected: commands dropped because the queue was already full
//     (outstanding >= depth). This is the backpressure signal — the caller logs it at
//     WARN with a grep-able prefix.
//   - duplicates: commands skipped because their command_id was already queued or
//     in-flight. The caller logs this at DEBUG; it is the expected, benign consequence
//     of at-least-once redelivery, not an operator-actionable condition.
//
// Order matters: the cap admits the first commands that fit and rejects the tail, and
// the dedup check runs before the capacity check so a redelivered duplicate is always
// classified as a duplicate (never lost, never miscounted as capacity pressure) even
// when the queue is full. It signals the consumer exactly when it admitted at least
// one command.
func (q *commandQueue) enqueue(cmds []command) (rejected, duplicates []command) {
	q.mu.Lock()
	admitted := 0
	for _, c := range cmds {
		id := c.CommandID
		if id != "" {
			if _, dup := q.inflight[id]; dup {
				duplicates = append(duplicates, c)
				continue
			}
		}
		if q.outstanding >= q.depth {
			rejected = append(rejected, c)
			continue
		}
		q.items = append(q.items, c)
		q.outstanding++
		if id != "" {
			q.inflight[id] = struct{}{}
		}
		admitted++
	}
	q.mu.Unlock()

	if admitted > 0 {
		q.signal()
	}
	return rejected, duplicates
}

// signal delivers the coalesced wake without ever blocking the producer: a buffer
// already holding a pending wake means the consumer has not yet consumed the last one,
// which is all a coalesced signal needs to convey.
func (q *commandQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// waitForWork blocks until enqueue signals that work may be available or ctx is
// cancelled. It returns true when the consumer should drain, false when ctx is done
// (shutdown) — the consumer then returns. It selects on ctx.Done() so a shutdown
// returns promptly rather than blocking until the next enqueue, exactly like the poll
// loop's inter-poll wait.
func (q *commandQueue) waitForWork(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-q.wake:
		return true
	}
}

// drain removes and returns every currently queued command in FIFO order, leaving them
// counted as in-flight (still occupying capacity and still deduplicated) until complete
// records them done. Draining the whole queue at once preserves the poll batch's own
// ordering — the retry/replace semantics executeBatch depends on — while the depth cap
// still bounds the batch's size.
func (q *commandQueue) drain() []command {
	q.mu.Lock()
	defer q.mu.Unlock()
	batch := q.items
	q.items = nil
	return batch
}

// complete records that batch has finished executing: it frees the batch's capacity and
// clears its dedup entries, so a genuinely new later delivery of the same command_id
// (e.g. after the report was lost) can be queued again. It is called after executeBatch
// returns, so the dedup entry lives from enqueue through the end of execution — exactly
// the window a redelivered duplicate must be caught in.
func (q *commandQueue) complete(batch []command) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, c := range batch {
		if q.outstanding > 0 {
			q.outstanding--
		}
		if c.CommandID != "" {
			delete(q.inflight, c.CommandID)
		}
	}
}

// outstandingNow reports the current queued-plus-in-flight command count, for the
// steward_uplink_command_queue_depth gauge.
func (q *commandQueue) outstandingNow() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.outstanding
}

// commandIDs joins cmds' command_ids for a log field, so a rejected/duplicate log line
// names exactly which commands were affected (an operator can grep the prefix, then
// read the ids). An empty command_id renders as an empty element rather than being
// dropped, so the count of listed ids always matches len(cmds).
func commandIDs(cmds []command) string {
	ids := make([]string, len(cmds))
	for i, c := range cmds {
		ids[i] = c.CommandID
	}
	return strings.Join(ids, ",")
}

// runtimeRefs joins cmds' runtime_refs for a log field, the instance-addressing
// companion to commandIDs: together they identify each rejected command both by its own
// id and by the instance it targeted.
func runtimeRefs(cmds []command) string {
	refs := make([]string, len(cmds))
	for i, c := range cmds {
		refs[i] = c.RuntimeRef
	}
	return strings.Join(refs, ",")
}
