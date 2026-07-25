package gatewayclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxServiceReadinessBytes = 16 << 10

// ServiceReadinessError reports a complete non-200 health response without
// retaining or exposing its body.
type ServiceReadinessError struct {
	Status int
}

func (err *ServiceReadinessError) Error() string {
	return fmt.Sprintf("Gateway Hermes service is not ready (HTTP %d)", err.Status)
}

// HermesReady checks the fixed read-only health path of one exact service
// grant. It does not accept a caller-selected operation path or return the
// service body, so it cannot become an ambient HTTP client.
func (c *Client) HermesReady(ctx context.Context, servicePath string) error {
	if !validServicePath(servicePath) {
		return errors.New("Hermes readiness check has an invalid service path")
	}
	target := c.baseURL + strings.TrimSuffix(servicePath, "/") + "/health"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header = http.Header{
		"Accept":          {"application/json"},
		"Accept-Encoding": {"identity"},
		"Authorization":   {"Bearer " + c.token},
		"User-Agent":      {"steward"},
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("call Gateway Hermes readiness: %w", err)
	}
	defer response.Body.Close()
	if response.ContentLength > maxServiceReadinessBytes {
		return errors.New("Gateway Hermes readiness response exceeds 16 KiB")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxServiceReadinessBytes+1))
	if err != nil {
		return fmt.Errorf("read Gateway Hermes readiness response: %w", err)
	}
	if len(raw) > maxServiceReadinessBytes {
		return errors.New("Gateway Hermes readiness response exceeds 16 KiB")
	}
	if response.StatusCode != http.StatusOK {
		return &ServiceReadinessError{Status: response.StatusCode}
	}
	return nil
}
