package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxControlResponse = 1 << 20

// ControlClient is the Executor's narrow, host-local client for the gateway
// Unix socket. It deliberately exposes grants rather than a generic HTTP
// method so an Executor bug cannot turn it into an ambient proxy capability.
type ControlClient struct {
	client *http.Client
}

func NewControlClient(socket string) (*ControlClient, error) {
	if !validAbsolutePath(socket) {
		return nil, errors.New("gateway control socket must be a clean absolute path")
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	return &ControlClient{client: &http.Client{Transport: transport, Timeout: 10 * time.Second}}, nil
}

func (c *ControlClient) Register(ctx context.Context, grant Grant) error {
	return c.call(ctx, http.MethodPost, "/v1/grants", grant, http.StatusCreated)
}

func (c *ControlClient) Inspect(ctx context.Context, grantID string) (Grant, error) {
	if !validGrantID(grantID) {
		return Grant{}, errors.New("invalid gateway grant ID")
	}
	var grant Grant
	if err := c.callInto(ctx, http.MethodGet, "/v1/grants/"+url.PathEscape(grantID), nil, http.StatusOK, &grant); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

func (c *ControlClient) Activate(ctx context.Context, grantID string) error {
	return c.grantAction(ctx, grantID, "activate")
}

func (c *ControlClient) Deactivate(ctx context.Context, grantID string) error {
	return c.grantAction(ctx, grantID, "deactivate")
}

func (c *ControlClient) Unregister(ctx context.Context, grantID string) error {
	if !validGrantID(grantID) {
		return errors.New("invalid gateway grant ID")
	}
	return c.call(ctx, http.MethodDelete, "/v1/grants/"+url.PathEscape(grantID), nil, http.StatusNoContent)
}

func (c *ControlClient) grantAction(ctx context.Context, grantID, action string) error {
	if !validGrantID(grantID) {
		return errors.New("invalid gateway grant ID")
	}
	return c.call(ctx, http.MethodPost, "/v1/grants/"+url.PathEscape(grantID)+"/"+action, nil, http.StatusOK)
}

func (c *ControlClient) call(ctx context.Context, method, path string, body any, want int) error {
	return c.callInto(ctx, method, path, body, want, nil)
}

func (c *ControlClient) callInto(ctx context.Context, method, path string, body any, want int, target any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(raw) > maxConfigBytes {
			return errors.New("gateway control request exceeds limit")
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://gateway"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxControlResponse+1))
	if err != nil {
		return err
	}
	if len(raw) > maxControlResponse {
		return errors.New("gateway control response exceeds limit")
	}
	if response.StatusCode == want {
		if target != nil {
			if len(raw) == 0 || json.Unmarshal(raw, target) != nil {
				return errors.New("gateway control response is invalid")
			}
		}
		return nil
	}
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &payload) == nil && payload.Message != "" {
		return fmt.Errorf("gateway %s: %s", payload.Error, payload.Message)
	}
	return fmt.Errorf("gateway returned HTTP %d", response.StatusCode)
}

func validAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.ContainsRune(value, '\x00') && value == strings.TrimSuffix(value, "/")
}
