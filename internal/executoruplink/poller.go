package executoruplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	stewarduplink "github.com/hardrails/steward/internal/uplink"
)

const maxWireBytes = 1 << 20
const maxCommandsPerPoll = 128
const maxBackoff = 5 * time.Minute

type pollResponse struct {
	Commands []command `json:"commands"`
}

type reportResponse struct {
	Applied bool `json:"applied"`
}

// Config enables the optional generic Executor uplink. Plain HTTP is refused for
// remote hosts unless the operator explicitly acknowledges it; loopback remains
// available for local development and appliance-side reverse proxies.
type Config struct {
	BaseURL           string
	CredentialPath    string
	PollInterval      time.Duration
	AllowInsecureHTTP bool
	HTTPClient        *http.Client
	Logger            *slog.Logger
	Handler           http.Handler
	LocalToken        string
	State             *StateStore
}

type Poller struct {
	pollURL, reportURL string
	credentialPath     string
	expected           *stewarduplink.Credential
	interval           time.Duration
	client             *http.Client
	logger             *slog.Logger
	dispatcher         dispatcher
}

func NewPoller(cfg Config) (*Poller, error) {
	if cfg.PollInterval <= 0 || cfg.Handler == nil || cfg.LocalToken == "" || cfg.State == nil {
		return nil, errors.New("uplink requires a positive poll interval, local handler/token, and state store")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, fmt.Errorf("uplink URL must be an absolute http(s) URL")
	}
	if base.Scheme == "http" && !cfg.AllowInsecureHTTP && !isLoopbackHost(base.Hostname()) {
		return nil, errors.New("remote uplink HTTP is disabled; use HTTPS or explicitly allow insecure HTTP")
	}
	credential, err := stewarduplink.LoadCredential(cfg.CredentialPath)
	if err != nil {
		return nil, err
	}
	pollURL, _ := url.JoinPath(cfg.BaseURL, "executor-uplink", "poll")
	reportURL, _ := url.JoinPath(cfg.BaseURL, "executor-uplink", "report")
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Poller{
		pollURL: pollURL, reportURL: reportURL, credentialPath: cfg.CredentialPath,
		expected: credential, interval: cfg.PollInterval, client: client, logger: logger,
		dispatcher: dispatcher{
			handler: cfg.Handler, token: cfg.LocalToken, tenantID: credential.TenantID,
			nodeID: credential.NodeID, state: cfg.State,
		},
	}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (p *Poller) Run(ctx context.Context) {
	failures := 0
	for {
		if err := p.pollOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			p.logger.Warn("executor uplink poll failed", "error", err, "failures", failures)
		} else {
			failures = 0
		}
		wait := p.interval
		for i := 0; i < failures && wait < maxBackoff; i++ {
			wait *= 2
			if wait > maxBackoff {
				wait = maxBackoff
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (p *Poller) pollOnce(ctx context.Context) error {
	credential, err := stewarduplink.LoadCredential(p.credentialPath)
	if err != nil {
		return err
	}
	if credential.TenantID != p.expected.TenantID || credential.NodeID != p.expected.NodeID {
		return errors.New("rotated uplink credential changed tenant_id or node_id; refusing it")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.pollURL, strings.NewReader(`{}`))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+credential.Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return wireError("poll", resp)
	}
	var payload pollResponse
	raw, err := readBounded(resp.Body, maxWireBytes)
	if err != nil {
		return fmt.Errorf("read poll response: %w", err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("decode poll response: %w", err)
	}
	if len(payload.Commands) > maxCommandsPerPoll {
		return fmt.Errorf("poll returned %d commands, limit is %d", len(payload.Commands), maxCommandsPerPoll)
	}
	for _, cmd := range payload.Commands {
		rep := p.dispatcher.execute(ctx, cmd)
		if err := p.sendReport(ctx, credential.Credential, rep); err != nil {
			return err
		}
	}
	return nil
}

func (p *Poller) sendReport(ctx context.Context, credential string, report report) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(raw) > maxWireBytes {
		return errors.New("uplink report exceeds wire limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.reportURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return wireError("report", resp)
	}
	var response reportResponse
	responseBody, err := readBounded(resp.Body, maxWireBytes)
	if err != nil {
		return fmt.Errorf("read report response: %w", err)
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return fmt.Errorf("decode report response: %w", err)
	}
	return nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("response exceeds %d byte limit", limit)
	}
	return raw, nil
}

func wireError(operation string, resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("uplink %s returned HTTP %d: %s", operation, resp.StatusCode, strings.TrimSpace(string(raw)))
}
