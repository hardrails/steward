package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"time"
)

const (
	// MaxBackoff caps the exponential backoff between failed polls, and is also the
	// ceiling applied to the base poll interval itself (see backoffDuration): a
	// blackholed or mid-deploy control plane is retried at most this often, so a
	// dark node's poll traffic and logs stay bounded. Exported so cmd/steward can
	// warn at startup when -uplink-poll-interval exceeds it.
	MaxBackoff = 5 * time.Minute
	// jitterFraction is the +/- proportion of each wait randomized to decorrelate a
	// fleet that restarts together (a control-plane redeploy, a power event).
	jitterFraction = 0.20
	// skewFailures pins the backoff to MaxBackoff for an other-4xx (probable version
	// skew): a value large enough that backoffDuration reaches the cap for any base.
	skewFailures = 62
	// httpTimeout bounds every poll/report round-trip so a blackholed control plane
	// cannot wedge the loop forever.
	httpTimeout = 30 * time.Second
	// maxUplinkBodyBytes caps every poll/report HTTP body Steward reads or writes,
	// at the same 1 MiB the inbound REST API bounds a request body to
	// (internal/server.maxRequestBodyBytes). The outbound channel gets the same
	// defense as the inbound one: a poll response over the cap is a clean, logged
	// rejection (this poll is dropped and retried next cycle — see poll), and a
	// report body over the cap is refused before it is sent (see sendReport), so a
	// hostile or buggy control plane can never make Steward read or send an
	// unbounded body into memory.
	maxUplinkBodyBytes = 1 << 20
	// pollBody is the (empty) poll request body: the server derives the node from
	// the credential, so no node_id or heartbeat payload is sent.
	pollBody = `{}`
	// persistentFailureThreshold is how many consecutive poll failures (with no
	// successful poll yet) the readiness gate treats as a sustained, persistent
	// failure rather than a transient blip (see Metrics.readiness and
	// Poller.Ready). With the exponential backoff a handful of failures already
	// spans minutes, and a version-skew rejection pins the failure count at the
	// cap immediately (skewFailures), so this small value drains a genuinely-stuck
	// fresh node quickly while never flapping readiness on one lost poll.
	persistentFailureThreshold = 3
	// queueBackpressureThreshold is how many consecutive poll cycles must each reject
	// at least one command for a full command queue (see commandQueue) before the
	// readiness gate reports the node not-ready (see Metrics.readiness and
	// Poller.Ready). A single over-full poll is an expected momentary spike the
	// control plane redelivers next cycle, not a reason to drain the node; only a
	// SUSTAINED inability to admit the backlog — the queue full for several polls in a
	// row — means the node is genuinely not keeping up and should stop being routed
	// new work. A cycle that admits everything resets the streak, so a node that
	// catches up becomes ready again on its very next clean poll (never flapping on
	// one burst).
	queueBackpressureThreshold = 3
	// DefaultCredentialWatchInterval is how often Run re-reads the credential file
	// while paused after a fatal 401/403 rejection (see waitForCredentialChange),
	// when Config.CredentialWatchInterval is unset. This loop makes no outbound
	// HTTP request per tick -- it only reads a local file -- so a value this small
	// does not hammer the control plane; it is still a fixed interval, never a
	// busy loop, so a permanently-wrong credential costs one small file read every
	// few seconds, not spinning CPU.
	DefaultCredentialWatchInterval = 5 * time.Second
)

// pollClass is how a poll round-trip's outcome is classified for the loop.
type pollClass int

const (
	classOK        pollClass = iota // 2xx: process commands, reset backoff.
	classTransient                  // network / timeout / 5xx / 429: WARN, exponential backoff.
	classSkew                       // other 4xx (400/404): ERROR, back off at the cap.
	classFatal                      // 401/403: ERROR naming the remedy, stop the loop.
)

// Config configures a Poller. BaseURL, Credential, and NodeID come from the loaded
// credential and the -uplink-url flag; PollInterval is the base cadence. HTTPClient
// and Logger are optional (defaults are supplied).
type Config struct {
	BaseURL      string
	Credential   string
	NodeID       string
	PollInterval time.Duration
	HTTPClient   *http.Client
	Logger       *slog.Logger

	// CredentialPath is the on-disk path Credential was loaded from (see
	// LoadCredential). Optional: when set, a fatal 401/403 rejection pauses Run
	// instead of stopping it, and watches this file until it changes to a new,
	// valid credential for this node -- see waitForCredentialChange. When empty,
	// Run keeps the pre-hot-reload behavior: a fatal rejection stops the loop and
	// a restart (with a corrected credential in place) is the only way to resume.
	CredentialPath string
	// CredentialWatchInterval overrides DefaultCredentialWatchInterval for the
	// wait loop above. Optional; meaningful only when CredentialPath is set.
	// Exposed the same way PollInterval is, so a test can drive it fast.
	CredentialWatchInterval time.Duration

	// CommandQueueDepth bounds how many received-but-not-yet-executed commands the
	// poll loop holds at once (queued plus in-flight): a poll cycle whose commands
	// would exceed it has its excess rejected (logged, left for the control plane to
	// redeliver) rather than committing the node to unbounded work — see commandQueue.
	// Optional: a value <= 0 uses DefaultCommandQueueDepth. cmd/steward validates the
	// operator-facing value fail-closed before constructing a Poller (see
	// prepareRuntime), so only a library caller relies on this default.
	CommandQueueDepth int

	// AuditLogger, when non-nil, receives one record per executed command's
	// terminal outcome (see dispatcher.recordOutcome and cmd/steward's
	// -audit-log-file flag). The caller owns its whole lifecycle -- opening it
	// (NewAuditLogger) and closing it once done with it -- independently of this
	// Poller: cmd/steward's -audit-log-file is accepted even when the uplink
	// itself is disabled (the file is opened but never wired into a Poller), so
	// a Poller-scoped close would not be reachable in that case anyway. A nil
	// value disables command auditing, the default.
	AuditLogger *AuditLogger
}

// Poller is the outbound uplink loop: it polls the control plane for queued
// lifecycle commands, executes each against the tracker, and reports the result. A
// single background goroutine drives it; it is not safe for concurrent Run calls.
type Poller struct {
	httpClient   *http.Client
	pollURL      string
	reportURL    string
	credential   string
	baseInterval time.Duration
	logger       *slog.Logger
	dispatcher   *dispatcher

	// credentialPath and credentialWatchInterval drive waitForCredentialChange.
	// credentialPath is empty when hot-reload is not configured (see Config).
	credentialPath          string
	credentialWatchInterval time.Duration

	// queue is the bounded, deduplicating command queue between polling and
	// execution: the poll loop (producer) enqueues each poll's commands and a
	// consumer goroutine drains and executes them (see Run/admit/consume). Always
	// non-nil (see NewPoller).
	queue *commandQueue

	// metrics is always non-nil (see NewPoller) so command/poll counters are
	// always collected; the optional /metrics endpoint decides only whether to
	// render them (see MetricsSnapshot).
	metrics *Metrics
}

// NewPoller validates cfg and builds a Poller driving tracker. It fails closed on a
// missing field or a URL that is not an absolute http(s) URL so a misconfiguration
// is a startup error, not a loop that silently never works.
func NewPoller(tracker Tracker, cfg Config) (*Poller, error) {
	switch {
	case cfg.BaseURL == "":
		return nil, errors.New("uplink base URL is required")
	case cfg.Credential == "":
		return nil, errors.New("uplink credential is required")
	case cfg.NodeID == "":
		return nil, errors.New("uplink node_id is required")
	case cfg.PollInterval <= 0:
		return nil, fmt.Errorf("uplink poll interval must be positive, got %s", cfg.PollInterval)
	}
	// url.Parse alone is not enough: it happily accepts a bare hostname like
	// "control-plane.example" (a plausible forgot-the-scheme operator typo) with no
	// error, an empty Scheme, and no Host — every subsequent poll would then fail
	// with "unsupported protocol scheme ''" forever instead of failing here at
	// startup. Require an absolute http(s) URL explicitly.
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid uplink URL %q: need an absolute http(s) URL, e.g. https://control-plane.example (set -uplink-url)", cfg.BaseURL)
	}
	pollURL, err := url.JoinPath(cfg.BaseURL, "uplink", "poll")
	if err != nil {
		return nil, fmt.Errorf("invalid uplink URL %q: %w", cfg.BaseURL, err)
	}
	reportURL, err := url.JoinPath(cfg.BaseURL, "uplink", "report")
	if err != nil {
		return nil, fmt.Errorf("invalid uplink URL %q: %w", cfg.BaseURL, err)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: httpTimeout}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	watchInterval := cfg.CredentialWatchInterval
	if watchInterval <= 0 {
		watchInterval = DefaultCredentialWatchInterval
	}
	// A non-positive CommandQueueDepth falls back to the default, mirroring how
	// CredentialWatchInterval and PollInterval's HTTPClient default are supplied:
	// cmd/steward always passes an operator-validated positive value (see
	// prepareRuntime), so this fallback only serves a library caller that omits it.
	queueDepth := cfg.CommandQueueDepth
	if queueDepth <= 0 {
		queueDepth = DefaultCommandQueueDepth
	}
	metrics := &Metrics{}
	return &Poller{
		httpClient:   client,
		pollURL:      pollURL,
		reportURL:    reportURL,
		credential:   cfg.Credential,
		baseInterval: cfg.PollInterval,
		logger:       logger,
		dispatcher: &dispatcher{
			tracker: tracker,
			nodeID:  cfg.NodeID,
			logger:  logger,
			metrics: metrics,
			audit:   cfg.AuditLogger,
		},
		credentialPath:          cfg.CredentialPath,
		credentialWatchInterval: watchInterval,
		queue:                   newCommandQueue(queueDepth),
		metrics:                 metrics,
	}, nil
}

// MetricsSnapshot returns a point-in-time copy of this Poller's live metrics
// (poll latency, poll count, command success/failure counters, current
// backoff), for the optional /metrics HTTP endpoint (see
// internal/server.UplinkMetrics). Safe to call concurrently with Run.
func (p *Poller) MetricsSnapshot() Snapshot {
	return p.metrics.snapshot(p.baseInterval, p.queue.depth)
}

// Ready reports whether this poll loop is ready to serve traffic and, when not, a
// human detail naming why. It backs the GET /v1/readiness gate (see
// internal/server.UplinkMetrics and handleReadiness). A node is NOT ready when
// either:
//   - its command queue has been full for queueBackpressureThreshold consecutive
//     poll cycles — it is not keeping up with its command backlog, so routing it
//     more work is counterproductive; or
//   - it has never completed a successful poll AND is in a persistent-failure state
//     (a rejected credential, or persistentFailureThreshold consecutive failures).
//
// Safe to call concurrently with Run.
func (p *Poller) Ready() (ready bool, detail string) {
	return p.metrics.readiness(persistentFailureThreshold, queueBackpressureThreshold)
}

// Run drives the poll loop until ctx is cancelled. The inter-poll wait and every
// in-flight request are cancelled by ctx, so a shutdown signal returns promptly.
// It leaves the rest of Steward (an inbound REST listener, if bound) running.
//
// A fatal 401/403 no longer stops the loop outright when Config.CredentialPath is
// set (the normal case: cmd/steward always sets it): Run pauses, logs the
// rejection, and watches the credential file until it changes to a new, valid
// credential for this node -- see waitForCredentialChange -- then resumes polling
// with it. If the NEW credential is rejected too, Run pauses and watches again;
// it never busy-loops or crashes. Only when CredentialPath is empty does a fatal
// rejection stop Run outright, the pre-hot-reload behavior, since there is then
// no file to watch and a restart is the only way to recover.
func (p *Poller) Run(ctx context.Context) {
	// The consumer drains the bounded queue and executes commands in its own
	// goroutine, so a slow batch (many state-file writes) never stalls polling and
	// the queue can hold a backlog across poll cycles — the two properties the
	// bounded queue exists to provide (see commandQueue). Run does not return until
	// the consumer has also stopped, so main's shutdown wait covers both goroutines
	// and no command executes after Run returns.
	//
	// The consumer runs under a CHILD context cancelled the moment Run's producer
	// loop returns — not just when the parent ctx is cancelled. That matters for the
	// one path where the producer loop returns on its own with the parent ctx still
	// live: a fatal 401/403 with no credential-hot-reload path (Config.CredentialPath
	// unset). Without the child cancel, the consumer would block forever in
	// waitForWork and Run's join below would deadlock. With it, the producer's return
	// stops the consumer too, exactly as a real shutdown would.
	consumerCtx, stopConsumer := context.WithCancel(ctx)
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		p.consume(consumerCtx)
	}()
	defer func() {
		stopConsumer()
		<-consumerDone
	}()

	failures := 0
	for {
		if !p.wait(ctx, p.nextWait(failures)) {
			return // ctx cancelled during the inter-poll wait.
		}

		commands, class, err := p.poll(ctx)
		if ctx.Err() != nil {
			return // ctx cancelled during an in-flight poll.
		}

		switch class {
		case classOK:
			failures = 0
			p.metrics.recordPollSuccess() // readiness: the node has reached its control plane.
			p.admit(commands)
		case classTransient:
			failures++
			p.logger.Warn("uplink poll failed; backing off and retrying",
				"err", err, "consecutive_failures", failures,
				"next_backoff", backoffDuration(p.baseInterval, failures).String())
		case classSkew:
			failures = skewFailures
			p.logger.Error("uplink poll rejected (probable control-plane version skew); backing off at the cap and retrying",
				"err", err, "next_backoff", MaxBackoff.String())
		case classFatal:
			if p.credentialPath == "" {
				p.logger.Error("uplink credential rejected; stopping the poll loop — re-enroll this node, update the credential file, and restart",
					"err", err, "node_id", p.dispatcher.nodeID)
				return
			}
			// A rejected credential with the loop paused is a persistent-failure
			// state for the readiness gate — one the consecutive-failure count does
			// not capture on its own (a first-poll rejection leaves it at 0). Mark it
			// before the (blocking) wait and clear it only once a new credential
			// resumes the loop.
			p.metrics.setCredentialRejected(true)
			p.logger.Error("uplink credential rejected; pausing the poll loop and waiting for a new credential",
				"err", err, "node_id", p.dispatcher.nodeID, "path", p.credentialPath)
			if !p.waitForCredentialChange(ctx) {
				return // ctx cancelled while waiting: a real shutdown, not a resume.
			}
			p.metrics.setCredentialRejected(false)
			failures = 0
		}
		// Mirror the local failures count into the metrics gauge every iteration
		// (not just on change) -- simplest correct option: /metrics reads this
		// from a different goroutine than the one mutating failures, so the
		// gauge must be updated whenever failures could have changed, and every
		// switch arm above touches it.
		p.metrics.setConsecutiveFailures(failures)
	}
}

// waitForCredentialChange blocks, re-reading p.credentialPath every
// p.credentialWatchInterval, until ctx is cancelled (returns false: Run should
// stop, this is a shutdown, not a resume) or the file changes to a new, validly
// parseable credential for this node (returns true, having already updated
// p.credential to the new secret so the next poll uses it).
//
// The comparison is by CONTENT, not by mtime: it re-parses the file with
// LoadCredential and compares the decoded Credential (secret) field against the
// one just rejected. mtime alone is not trustworthy here -- some editors and
// deployment tools rewrite a file's mtime without changing its bytes (a
// permissions-preserving copy, a `touch`), which would otherwise trigger a
// pointless resume attempt with the SAME already-rejected secret, immediately
// failing again. A read/parse error (the file briefly absent, truncated, or
// syntactically invalid mid-write by a non-atomic external rotation tool) is the
// expected steady state while waiting, not a fatal condition: it is logged at
// DEBUG and retried on the next tick, exactly like an unchanged secret. Neither
// case busy-loops; both simply wait for the next fixed-interval tick.
//
// A file that now parses to a DIFFERENT node_id than this Poller was configured
// with is refused (logged at ERROR, wait continues): adopting it would silently
// re-identify this process as a different node rather than rotate its secret --
// a control-plane trust violation this loop must not paper over.
func (p *Poller) waitForCredentialChange(ctx context.Context) bool {
	for {
		if !p.wait(ctx, p.credentialWatchInterval) {
			return false
		}

		cred, err := LoadCredential(p.credentialPath)
		if err != nil {
			p.logger.Debug("uplink credential file is not yet readable while waiting for a new credential; retrying",
				"path", p.credentialPath, "err", err)
			continue
		}
		if cred.NodeID != p.dispatcher.nodeID {
			p.logger.Error("uplink credential file now names a different node_id than this process was started with; refusing to adopt it and continuing to wait",
				"path", p.credentialPath, "file_node_id", cred.NodeID, "this_node_id", p.dispatcher.nodeID)
			continue
		}
		if cred.Credential == p.credential {
			continue // Same secret as the one just rejected (e.g. an mtime-only touch); keep waiting.
		}

		p.logger.Info("uplink credential file changed; resuming the poll loop",
			"path", p.credentialPath, "node_id", p.dispatcher.nodeID)
		p.credential = cred.Credential
		return true
	}
}

// admit is the producer side of the bounded queue: it enqueues one poll cycle's
// commands, then logs and records what the queue could not admit. It never blocks the
// poll loop — a full queue rejects the excess rather than waiting for the consumer.
//
// The rejection log uses a grep-able "uplink command queue full:" prefix (mirroring
// reload.go's "sighup reload:" convention) and names the rejected commands by both
// command_id and runtime_ref, so an operator can see exactly which commands were
// deferred to a later poll cycle. A rejected command is not lost: it was never
// reported, so the control plane's claim lease redelivers it once the backlog drains.
// A duplicate (a command_id already queued or in-flight) is logged at DEBUG only — it
// is the benign, expected consequence of at-least-once redelivery, not an
// operator-actionable condition.
func (p *Poller) admit(commands []command) {
	rejected, duplicates := p.queue.enqueue(commands)

	if len(duplicates) > 0 {
		p.logger.Debug("uplink command queue: skipping redelivered commands already queued or in flight; they will not be executed twice",
			"duplicate_count", len(duplicates),
			"duplicate_command_ids", commandIDs(duplicates))
	}
	if len(rejected) > 0 {
		p.logger.Warn("uplink command queue full: rejecting excess commands this poll cycle; they will be redelivered by the control plane once the backlog drains",
			"queue_max_depth", p.queue.depth,
			"rejected_count", len(rejected),
			"rejected_command_ids", commandIDs(rejected),
			"rejected_runtime_refs", runtimeRefs(rejected))
		p.metrics.recordCommandsRejected(len(rejected))
	}
	// Feed the readiness gate: a cycle that rejected anything extends the
	// full-queue streak, a cycle that admitted everything (including an empty poll)
	// resets it. See Metrics.readiness and queueBackpressureThreshold.
	p.metrics.recordQueueCycle(len(rejected) > 0)
	p.metrics.setQueueDepth(p.queue.outstandingNow())
}

// consume is the consumer side of the bounded queue: it waits for work, drains the
// whole queue as one batch (preserving each poll batch's own ordering, which
// executeBatch's replace/retry semantics depend on), executes it, then marks the batch
// complete so its capacity and dedup entries are freed. It returns when ctx is
// cancelled — waitForWork selects on ctx.Done(), so a shutdown returns promptly and
// executeBatch itself bails between commands on a cancelled ctx.
func (p *Poller) consume(ctx context.Context) {
	for {
		if !p.queue.waitForWork(ctx) {
			return
		}
		batch := p.queue.drain()
		if len(batch) == 0 {
			continue // a spurious/coalesced wake with nothing queued; wait again.
		}
		p.executeBatch(ctx, batch)
		p.queue.complete(batch)
		p.metrics.setQueueDepth(p.queue.outstandingNow())
	}
}

// executeBatch runs each command in the SERVER'S OWN returned order — reordering
// nothing — then makes exactly one bounded retry pass over the start commands (and
// ONLY start; see below) that failed only because their instance was not yet known
// to the tracker.
//
// Reordering the batch is wrong. The server's claim query
// (node_uplink._orm.claim_pending_commands) has no ORDER BY, so the batch order is
// not guaranteed causal; more importantly, a single poll can carry a REPLACE —
// destroy(x) then provision(x) — and hoisting the provision ahead of the destroy
// would run them out of order and leave x destroyed instead of recreated.
// Processing in the given order and retrying a start's unknown-instance miss once
// closes BOTH the destroy-then-provision replace (nothing is reordered) and the
// original start-before-its-own-provision concern (the retry runs after the sibling
// provision), with no server-side wire change and no unbounded loop. (A wire-level
// ordering guarantee — an epoch/generation or causal sequence on runtime_ref — is a
// separate cross-repo follow-up in the node_uplink primitive, not built here.)
//
// stop/hibernate deliberately do NOT get this deferral (a hosted review finding
// that narrowed an earlier, too-broad version of this fix): there is no legitimate
// case where a sibling provision in the same batch should make a stop/hibernate
// succeed after the fact, and deferring one would risk stopping/hibernating an
// instance the sibling provision just created — a new ordering inversion of the same
// class the destroy-then-provision fix above already closed. A stop/hibernate on an
// unknown instance reports failed on the first pass, exactly like every other
// terminal outcome.
//
// A report POST failure is logged at WARN and not retried: the server's claim lease
// redelivers the command with a bumped claim_generation, so the node stays
// stateless about outbound reports.
//
// A fenced command (see dispatcher.execute) sends no report and is never
// deferred to the retry pass: it is checked ahead of retry in both passes, so a
// command found stale on the first pass is dropped outright, and a start that is
// deferred and only becomes stale after its sibling provision runs (adopting a
// higher generation) is dropped on the retry pass instead of being reported.
func (p *Poller) executeBatch(ctx context.Context, commands []command) {
	var deferred []command
	for _, cmd := range commands {
		if ctx.Err() != nil {
			return
		}
		rep, retry, fenced := p.dispatcher.execute(cmd)
		if fenced {
			continue
		}
		if retry {
			// A start whose instance is not yet known: defer one retry (a sibling
			// provision later in this same batch may create it) rather than reporting
			// failed now. No report is sent for it in this pass. stop/hibernate never
			// set retry=true (see the executeBatch doc comment), so this branch only
			// ever defers a start.
			deferred = append(deferred, cmd)
			continue
		}
		if err := p.sendReport(ctx, rep); err != nil {
			p.logger.Warn("uplink report failed; the server will redeliver via its claim lease",
				"command_id", rep.CommandID, "err", err)
		}
	}
	// One bounded retry pass over the deferred starts. Each now runs after every
	// command from the first pass, so any sibling provision has had its chance. A
	// start still naming an unknown instance here fails for real — the existing
	// terminal outcome, delayed by exactly one pass, never an unbounded loop.
	for _, cmd := range deferred {
		if ctx.Err() != nil {
			return
		}
		rep, stillUnknown, fenced := p.dispatcher.execute(cmd)
		if fenced {
			continue
		}
		if stillUnknown {
			p.logger.Error("uplink start command still names an unknown instance after the retry pass; reporting failed — no provision for it arrived in this batch, so the control plane will reconcile and re-drive",
				"command_id", rep.CommandID)
		}
		if err := p.sendReport(ctx, rep); err != nil {
			p.logger.Warn("uplink report failed; the server will redeliver via its claim lease",
				"command_id", rep.CommandID, "err", err)
		}
	}
}

// nextWait is the jittered wait before the next poll: the steady-state interval
// when there are no failures, or the exponential backoff otherwise.
func (p *Poller) nextWait(failures int) time.Duration {
	return jitter(backoffDuration(p.baseInterval, failures))
}

// wait sleeps for d against ctx using a Timer selected against ctx.Done(). It
// returns true if the full wait elapsed, false if ctx was cancelled first.
func (p *Poller) wait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// poll POSTs to /uplink/poll and classifies the outcome. On classOK it returns the
// decoded commands; otherwise commands is nil and err describes the condition.
//
// It records the round-trip latency into p.metrics for every attempt,
// success or failure alike: latency is the round-trip time itself, not a
// judgment about the outcome, and a struggling or blackholed control plane's
// slow/timed-out polls are exactly the signal an operator wants a latency
// gauge to surface.
func (p *Poller) poll(ctx context.Context) ([]command, pollClass, error) {
	start := time.Now()
	resp, err := p.post(ctx, p.pollURL, []byte(pollBody))
	p.metrics.recordPollLatency(time.Since(start))
	if err != nil {
		return nil, classTransient, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		body, tooLarge, err := readCappedBody(resp.Body)
		if err != nil {
			// A read error mid-body is the same class as a transport error: back
			// off and retry rather than executing a partial/empty batch.
			return nil, classTransient, fmt.Errorf("read poll response: %w", err)
		}
		if tooLarge {
			// A response past the cap is dropped whole, not truncated-and-parsed:
			// a truncated JSON prefix could decode into a partial, wrong command
			// batch. Reject cleanly and retry next cycle, the same posture the
			// inbound listener takes when a request body exceeds its 1 MiB cap.
			return nil, classTransient, fmt.Errorf("uplink poll response body exceeds the %d-byte cap; dropping this poll and retrying next cycle", maxUplinkBodyBytes)
		}
		var pr pollResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			// A 2xx with an unparseable body is a server bug; treat it as transient
			// rather than executing nothing forever silently.
			return nil, classTransient, fmt.Errorf("decode poll response: %w", err)
		}
		return pr.Commands, classOK, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		drain(resp.Body)
		return nil, classFatal, fmt.Errorf("uplink poll returned HTTP %d", resp.StatusCode)
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		drain(resp.Body)
		return nil, classTransient, fmt.Errorf("uplink poll returned HTTP %d", resp.StatusCode)
	default: // other 4xx
		drain(resp.Body)
		return nil, classSkew, fmt.Errorf("uplink poll returned HTTP %d", resp.StatusCode)
	}
}

// sendReport POSTs one report to /uplink/report. A non-2xx or transport error is
// returned to the caller (logged WARN, not retried). applied:false is the server's
// no-op signal, logged at INFO and not treated as an error.
func (p *Poller) sendReport(ctx context.Context, rep report) error {
	body, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	// Cap the outbound report body at the same bound as the inbound listener and
	// the poll response: an unexpectedly huge report (e.g. a pathological error
	// string in a command outcome) is refused before it is sent, rather than
	// pushing an unbounded body onto the control plane. The caller logs this at
	// WARN and does not retry; the server redelivers the command via its claim
	// lease, so no outcome is lost.
	if int64(len(body)) > maxUplinkBodyBytes {
		return fmt.Errorf("uplink report body is %d bytes, over the %d-byte cap; not sending it (the server will redeliver this command via its claim lease)", len(body), maxUplinkBodyBytes)
	}
	resp, err := p.post(ctx, p.reportURL, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drain(resp.Body)
		return fmt.Errorf("uplink report returned HTTP %d", resp.StatusCode)
	}
	// The report response is read with the same over-cap rejection the poll
	// response uses, not a bare LimitReader: a LimitReader would let json.Decode
	// succeed on the leading {"applied":...} and silently ignore an oversized
	// padded tail, whereas readCappedBody detects and rejects the over-cap body.
	respBody, tooLarge, err := readCappedBody(resp.Body)
	if err != nil {
		return fmt.Errorf("read report response: %w", err)
	}
	if tooLarge {
		return fmt.Errorf("uplink report response body exceeds the %d-byte cap", maxUplinkBodyBytes)
	}
	var rr reportResponse
	if err := json.Unmarshal(respBody, &rr); err != nil {
		return fmt.Errorf("decode report response: %w", err)
	}
	if !rr.Applied {
		p.logger.Info("uplink report was not applied (fenced/stale/duplicate); no retry needed",
			"command_id", rep.CommandID, "claim_generation", rep.ClaimGeneration)
	}
	return nil
}

// post issues an authenticated JSON POST built with ctx so a shutdown cancels an
// in-flight request.
func (p *Poller) post(ctx context.Context, endpoint string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.credential)
	return p.httpClient.Do(req)
}

// backoffDuration is the capped exponential backoff for a given number of
// consecutive failures: base for zero failures, base*2^failures otherwise, clamped
// to MaxBackoff. It guards against int64 overflow so an absurd failure count still
// returns the cap rather than a wrapped negative duration. A base at or above
// MaxBackoff (an operator-configured -uplink-poll-interval past the cap) is
// clamped even at zero failures — see NewPoller's caller in cmd/steward, which
// warns about this at startup so it is not a silent surprise.
func backoffDuration(base time.Duration, failures int) time.Duration {
	if base >= MaxBackoff {
		return MaxBackoff
	}
	d := base
	for i := 0; i < failures; i++ {
		d *= 2
		if d <= 0 || d >= MaxBackoff {
			return MaxBackoff
		}
	}
	return d
}

// jitter randomizes d by +/- jitterFraction using math/rand/v2 (auto-seeded, so no
// setup and no fleet-wide correlation). The result stays positive because the
// fraction is well under 1.
func jitter(d time.Duration) time.Duration {
	delta := float64(d) * jitterFraction
	offset := (rand.Float64()*2 - 1) * delta
	return time.Duration(float64(d) + offset)
}

// drain reads and discards up to maxUplinkBodyBytes of body so an HTTP/1.1
// keep-alive connection can be reused before Close.
func drain(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxUplinkBodyBytes))
}

// readCappedBody reads r into memory bounded by maxUplinkBodyBytes, reading one
// byte past the cap so an over-cap body is detected rather than silently
// truncated. It returns the bytes read (the truncated prefix when tooLarge is
// true, which the caller must reject rather than parse), whether the body
// exceeded the cap, and any read error. The read is never unbounded: at most
// maxUplinkBodyBytes+1 bytes are ever buffered.
func readCappedBody(r io.Reader) (data []byte, tooLarge bool, err error) {
	data, err = io.ReadAll(io.LimitReader(r, maxUplinkBodyBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxUplinkBodyBytes {
		return data[:maxUplinkBodyBytes], true, nil
	}
	return data, false, nil
}
