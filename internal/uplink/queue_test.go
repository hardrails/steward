package uplink

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// qcmd builds a distinct provision command whose command_id and instance_id both
// derive from id, for the queue's own unit tests (which care about command identity,
// not lifecycle semantics).
func qcmd(id string) command {
	return cmd(id, "node-7", "inst-"+id, kindProvision, "", 1)
}

// TestCommandQueueAdmitsUpToDepthAndRejectsExcess pins the capacity boundary: a queue
// of depth D admits the first D commands in order and rejects the rest, so a mutant
// that flips >= to > (off-by-one) or reorders admit/reject is caught.
func TestCommandQueueAdmitsUpToDepthAndRejectsExcess(t *testing.T) {
	q := newCommandQueue(2)
	rejected, duplicates := q.enqueue([]command{qcmd("a"), qcmd("b"), qcmd("c")})

	if len(duplicates) != 0 {
		t.Fatalf("duplicates = %d, want 0 (all ids distinct)", len(duplicates))
	}
	if len(rejected) != 1 {
		t.Fatalf("rejected = %d, want 1 (only 2 of 3 fit)", len(rejected))
	}
	if rejected[0].CommandID != "c" {
		t.Errorf("rejected the wrong command %q, want c (the tail is rejected, the head admitted)", rejected[0].CommandID)
	}
	if got := q.outstandingNow(); got != 2 {
		t.Errorf("outstanding = %d, want 2 (the admitted a and b)", got)
	}

	// Boundary: a batch of exactly depth admits all, rejects none.
	q2 := newCommandQueue(3)
	rej, _ := q2.enqueue([]command{qcmd("a"), qcmd("b"), qcmd("c")})
	if len(rej) != 0 {
		t.Errorf("a batch of exactly depth rejected %d, want 0", len(rej))
	}
	if got := q2.outstandingNow(); got != 3 {
		t.Errorf("outstanding = %d, want 3 (exactly depth)", got)
	}
}

// TestCommandQueueDeduplicatesByCommandID proves a command whose command_id is already
// outstanding is skipped as a duplicate — not admitted a second time, and not
// miscounted as capacity pressure — while a distinct sibling in the same batch is
// admitted normally.
func TestCommandQueueDeduplicatesByCommandID(t *testing.T) {
	q := newCommandQueue(10)
	q.enqueue([]command{qcmd("a")})

	rejected, duplicates := q.enqueue([]command{qcmd("a"), qcmd("b")})
	if len(rejected) != 0 {
		t.Errorf("rejected = %d, want 0 (capacity was ample)", len(rejected))
	}
	if len(duplicates) != 1 || duplicates[0].CommandID != "a" {
		t.Fatalf("duplicates = %+v, want exactly [a] (already queued)", duplicates)
	}
	if got := q.outstandingNow(); got != 2 {
		t.Errorf("outstanding = %d, want 2 (a once + b), not 3 (a must not be queued twice)", got)
	}
}

// TestCommandQueueDedupSpansExecutionUntilComplete is the crux of the cross-cycle
// redelivery guard: a command stays deduplicated from enqueue through the END of its
// execution (drained but not yet completed), so a redelivery that arrives while its
// first copy is still executing is skipped — and only after complete does the same
// command_id become admittable again (a genuinely new later delivery, e.g. after a
// lost report).
func TestCommandQueueDedupSpansExecutionUntilComplete(t *testing.T) {
	q := newCommandQueue(10)
	q.enqueue([]command{qcmd("a")})

	batch := q.drain() // "a" is now executing: out of items, still in-flight.
	if len(batch) != 1 || batch[0].CommandID != "a" {
		t.Fatalf("drain = %+v, want exactly [a]", batch)
	}
	if got := q.outstandingNow(); got != 1 {
		t.Errorf("outstanding after drain = %d, want 1 (still executing, capacity not yet freed)", got)
	}

	// Redelivered while executing: still a duplicate, not queued again.
	_, duplicates := q.enqueue([]command{qcmd("a")})
	if len(duplicates) != 1 {
		t.Fatalf("a redelivery during execution was not deduplicated: duplicates = %d, want 1", len(duplicates))
	}
	if got := q.outstandingNow(); got != 1 {
		t.Errorf("outstanding = %d, want 1 (the redelivery must not add a second copy)", got)
	}

	q.complete(batch)
	if got := q.outstandingNow(); got != 0 {
		t.Errorf("outstanding after complete = %d, want 0 (capacity freed)", got)
	}

	// Now a fresh delivery of the same id is admittable again.
	rejected, duplicates := q.enqueue([]command{qcmd("a")})
	if len(rejected) != 0 || len(duplicates) != 0 {
		t.Fatalf("after complete, re-enqueue of a = (rejected %d, duplicates %d), want (0, 0) — it is admittable again", len(rejected), len(duplicates))
	}
	if got := q.outstandingNow(); got != 1 {
		t.Errorf("outstanding = %d, want 1 (a re-admitted after completing)", got)
	}
}

// TestCommandQueueEmptyCommandIDNeverDeduplicated proves an empty command_id (an
// out-of-contract command) is never collapsed onto a shared dedup key: two empty-id
// commands both occupy capacity rather than one silently masking the other.
func TestCommandQueueEmptyCommandIDNeverDeduplicated(t *testing.T) {
	q := newCommandQueue(10)
	c1 := cmd("", "node-7", "inst-1", kindProvision, "", 1)
	c2 := cmd("", "node-7", "inst-2", kindProvision, "", 1)

	rejected, duplicates := q.enqueue([]command{c1, c2})
	if len(rejected) != 0 || len(duplicates) != 0 {
		t.Fatalf("two empty-id commands = (rejected %d, duplicates %d), want (0, 0): an empty id must not dedup", len(rejected), len(duplicates))
	}
	if got := q.outstandingNow(); got != 2 {
		t.Errorf("outstanding = %d, want 2 (both empty-id commands counted, not collapsed to 1)", got)
	}

	// complete frees an empty-id command's capacity even though it holds no dedup key.
	q.complete(q.drain())
	if got := q.outstandingNow(); got != 0 {
		t.Errorf("outstanding after completing empty-id commands = %d, want 0", got)
	}
}

// TestCommandQueueDrainIsFIFOAndEmpties proves drain returns queued commands in arrival
// order (the ordering executeBatch's replace/retry logic depends on) and leaves the
// queue empty for the next drain, while the outstanding count is unchanged (draining is
// not completing).
func TestCommandQueueDrainIsFIFOAndEmpties(t *testing.T) {
	q := newCommandQueue(10)
	q.enqueue([]command{qcmd("a"), qcmd("b"), qcmd("c")})

	batch := q.drain()
	if len(batch) != 3 || batch[0].CommandID != "a" || batch[1].CommandID != "b" || batch[2].CommandID != "c" {
		t.Fatalf("drain = %+v, want [a b c] in FIFO order", batch)
	}
	if got := q.drain(); len(got) != 0 {
		t.Errorf("second drain = %+v, want empty (the first drain emptied the queue)", got)
	}
	if got := q.outstandingNow(); got != 3 {
		t.Errorf("outstanding after drain = %d, want 3 (still executing until complete)", got)
	}
}

// TestCommandQueueCompleteFreesCapacityForRedelivery proves that completing a full
// queue's batch frees exactly its capacity, so a command previously rejected can be
// admitted on the next attempt.
func TestCommandQueueCompleteFreesCapacityForRedelivery(t *testing.T) {
	q := newCommandQueue(2)
	q.enqueue([]command{qcmd("a"), qcmd("b")}) // full

	if rej, _ := q.enqueue([]command{qcmd("c")}); len(rej) != 1 {
		t.Fatalf("c rejected %d, want 1 (queue full)", len(rej))
	}

	q.complete(q.drain())
	if got := q.outstandingNow(); got != 0 {
		t.Fatalf("outstanding after completing the full batch = %d, want 0", got)
	}
	if rej, _ := q.enqueue([]command{qcmd("c")}); len(rej) != 0 {
		t.Errorf("c rejected %d after capacity was freed, want 0 (it fits now)", len(rej))
	}
}

// TestCommandQueueWaitForWorkSignalsAndCancels pins the consumer's wakeup contract:
// waitForWork returns false when ctx is cancelled (shutdown) and true after an enqueue
// signals available work.
func TestCommandQueueWaitForWorkSignalsAndCancels(t *testing.T) {
	q := newCommandQueue(10)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if q.waitForWork(cancelled) {
		t.Fatal("waitForWork on a cancelled ctx must return false (shutdown)")
	}

	q.enqueue([]command{qcmd("a")}) // signals wake
	if !q.waitForWork(context.Background()) {
		t.Fatal("waitForWork after an admitting enqueue must return true (work is available)")
	}
}

// TestCommandQueueEnqueueNeverBlocksWithoutAConsumer proves the coalesced,
// non-blocking wake: many enqueues with no consumer draining must not deadlock on the
// buffered wake channel (a mutant that made the send blocking would hang here).
func TestCommandQueueEnqueueNeverBlocksWithoutAConsumer(t *testing.T) {
	q := newCommandQueue(1000)
	for i := 0; i < 100; i++ {
		q.enqueue([]command{qcmd(fmt.Sprintf("c-%d", i))})
	}
	if got := q.outstandingNow(); got != 100 {
		t.Fatalf("outstanding = %d, want 100 (every enqueue admitted, none blocked)", got)
	}
}

// TestCommandQueueConcurrentProducerConsumerIsRaceFree drives enqueue from one
// goroutine and drain/complete from another under -race, proving the queue's locking is
// sound and that every distinct command is eventually executed exactly through the
// drain path despite capacity rejections and redeliveries.
func TestCommandQueueConcurrentProducerConsumerIsRaceFree(t *testing.T) {
	q := newCommandQueue(8)
	const total = 200

	ctx, cancel := context.WithCancel(context.Background())
	var executed sync.Map
	var executedCount int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if !q.waitForWork(ctx) {
				return
			}
			batch := q.drain()
			for _, c := range batch {
				if _, loaded := executed.LoadOrStore(c.CommandID, struct{}{}); !loaded {
					atomic.AddInt64(&executedCount, 1)
				}
			}
			q.complete(batch)
		}
	}()

	// The producer re-offers only the commands not yet executed, mirroring a control
	// plane that stops redelivering a command once it has been reported done. (Naively
	// re-offering the whole set would keep re-admitting the just-completed head and
	// starve the tail — an artifact of the test, not the queue.)
	deadline := time.After(5 * time.Second)
	for atomic.LoadInt64(&executedCount) < total {
		var offer []command
		for i := 0; i < total; i++ {
			id := fmt.Sprintf("c-%d", i)
			if _, ok := executed.Load(id); !ok {
				offer = append(offer, qcmd(id))
			}
		}
		q.enqueue(offer) // capacity rejections and in-flight dups are fine; re-offered next loop.
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("only %d/%d distinct commands executed", atomic.LoadInt64(&executedCount), total)
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
}
