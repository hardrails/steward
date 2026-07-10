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
	// maxBackoff caps the exponential backoff between failed polls. A blackholed or
	// mid-deploy control plane is retried at most this often, so a dark node's poll
	// traffic and logs stay bounded.
	maxBackoff = 5 * time.Minute
	// jitterFraction is the +/- proportion of each wait randomized to decorrelate a
	// fleet that restarts together (a control-plane redeploy, a power event).
	jitterFraction = 0.20
	// skewFailures pins the backoff to maxBackoff for an other-4xx (probable version
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
// missing field or an unparseable URL so a misconfiguration is a startup error, not
// a loop that silently never works.
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
	if _, err := url.Parse(cfg.BaseURL); err != nil {
		return nil, fmt.Errorf("invalid uplink URL %q: %w", cfg.BaseURL, err)
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
				"err", err, "next_backoff", maxBackoff.String())
		case classFatal:
			p.logger.Error("uplink credential rejected; stopping the poll loop — re-enroll this node, update the credential file, and restart",
				"err", err, "node_id", p.dispatcher.nodeID)
			return
		}
	}
}

// executeBatch runs each command (provisions first) and reports its result. A
// report POST failure is logged at WARN and not retried: the server's claim lease
// redelivers the command with a bumped claim_generation, so the node stays
// stateless about outbound reports.
func (p *Poller) executeBatch(ctx context.Context, commands []command) {
	for _, cmd := range orderProvisionsFirst(commands) {
		if ctx.Err() != nil {
			return
		}
		rep := p.dispatcher.execute(cmd)
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
// to maxBackoff. It guards against int64 overflow so an absurd failure count still
// returns the cap rather than a wrapped negative duration.
func backoffDuration(base time.Duration, failures int) time.Duration {
	if base >= maxBackoff {
		return maxBackoff
	}
	d := base
	for i := 0; i < failures; i++ {
		d *= 2
		if d <= 0 || d >= maxBackoff {
			return maxBackoff
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
