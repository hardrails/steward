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
	// maxResponseBytes caps a poll/report response body read into memory.
	maxResponseBytes = 4 << 20
	// pollBody is the (empty) poll request body: the server derives the node from
	// the credential, so no node_id or heartbeat payload is sent.
	pollBody = `{}`
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
	return &Poller{
		httpClient:   client,
		pollURL:      pollURL,
		reportURL:    reportURL,
		credential:   cfg.Credential,
		baseInterval: cfg.PollInterval,
		logger:       logger,
		dispatcher:   &dispatcher{tracker: tracker, nodeID: cfg.NodeID, logger: logger},
	}, nil
}

// Run drives the poll loop until ctx is cancelled or a fatal credential rejection
// stops it. It returns when either happens; the caller closes its done channel. The
// inter-poll wait and every in-flight request are cancelled by ctx, so a shutdown
// signal returns promptly. A fatal 401/403 stops the loop but leaves the rest of
// Steward (an inbound REST listener, if bound) running.
func (p *Poller) Run(ctx context.Context) {
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
			p.executeBatch(ctx, commands)
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
			p.logger.Error("uplink credential rejected; stopping the poll loop — re-enroll this node, update the credential file, and restart",
				"err", err, "node_id", p.dispatcher.nodeID)
			return
		}
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
func (p *Poller) poll(ctx context.Context) ([]command, pollClass, error) {
	resp, err := p.post(ctx, p.pollURL, []byte(pollBody))
	if err != nil {
		return nil, classTransient, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		var pr pollResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&pr); err != nil {
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
	resp, err := p.post(ctx, p.reportURL, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drain(resp.Body)
		return fmt.Errorf("uplink report returned HTTP %d", resp.StatusCode)
	}
	var rr reportResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&rr); err != nil {
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

// drain reads and discards up to maxResponseBytes of body so an HTTP/1.1 keep-alive
// connection can be reused before Close.
func drain(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxResponseBytes))
}
