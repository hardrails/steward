package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/securefile"
	"github.com/hardrails/steward/internal/taskpermit"
)

const maxTaskWait = 15 * time.Minute

type taskRuntime struct {
	bundle       verifiedTaskBundle
	client       *gatewayclient.Client
	taskDigest   string
	permitDigest string
}

func submitTask(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("task submit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "owner-only lifecycle task bundle")
	gatewayURL := flags.String("gateway-url", "", "HTTP literal-loopback Gateway origin")
	tokenPath := flags.String("token-file", "", "owner-only Gateway bearer token")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *bundlePath == "" || *gatewayURL == "" || *tokenPath == "" || flags.NArg() != 0 {
		return errors.New("task submit requires -bundle, -gateway-url, and -token-file")
	}
	runtime, err := openCurrentTaskRuntime(*bundlePath, *gatewayURL, *tokenPath)
	if err != nil {
		return err
	}
	operation := runtime.bundle.Bundle.Operation
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(operation.MaxSeconds)*time.Second+30*time.Second)
	defer cancel()
	result, err := runtime.client.Submit(ctx, gatewayclient.TaskSubmission{
		ServicePath: runtime.bundle.Bundle.ServicePath, OperationPath: operation.Path,
		ContentType: operation.ContentType, Request: runtime.bundle.Request, Permit: runtime.bundle.Permit,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		TaskDigest   string                    `json:"task_digest"`
		PermitDigest string                    `json:"permit_digest"`
		RunID        string                    `json:"run_id"`
		Receipt      gatewayclient.TaskReceipt `json:"receipt"`
	}{
		TaskDigest: runtime.taskDigest, PermitDigest: runtime.permitDigest,
		RunID: result.RunID, Receipt: result.Receipt,
	})
}

func statusTask(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("task status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "owner-only lifecycle task bundle")
	gatewayURL := flags.String("gateway-url", "", "HTTP literal-loopback Gateway origin")
	tokenPath := flags.String("token-file", "", "owner-only Gateway bearer token")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *bundlePath == "" || *gatewayURL == "" || *tokenPath == "" || flags.NArg() != 0 {
		return errors.New("task status requires -bundle, -gateway-url, and -token-file")
	}
	runtime, err := openTaskRuntime(*bundlePath, *gatewayURL, *tokenPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	status, err := runtime.client.Status(ctx, runtime.taskDigest, runtime.permitDigest)
	if err != nil {
		return err
	}
	return writeTaskRuntimeStatus(stdout, status)
}

func observeTask(arguments []string, stdout io.Writer) (returnErr error) {
	flags := flag.NewFlagSet("task observe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "owner-only lifecycle task bundle")
	gatewayURL := flags.String("gateway-url", "", "HTTP literal-loopback Gateway origin")
	tokenPath := flags.String("token-file", "", "owner-only Gateway bearer token")
	resultPath := flags.String("result-out", "", "new owner-only file for a first terminal observation")
	discardResult := flags.Bool("discard-result", false, "discard a first terminal observation after verification")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *bundlePath == "" || *gatewayURL == "" || *tokenPath == "" || flags.NArg() != 0 {
		return errors.New("task observe requires -bundle, -gateway-url, and -token-file")
	}
	if (*resultPath != "") == *discardResult {
		return errors.New("task observe requires exactly one of -result-out or -discard-result")
	}
	runtime, err := openTaskRuntime(*bundlePath, *gatewayURL, *tokenPath)
	if err != nil {
		return err
	}
	reservation, err := reserveTaskResult(*resultPath)
	if err != nil {
		return err
	}
	defer func() {
		if reservation != nil {
			returnErr = errors.Join(returnErr, reservation.discard())
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	status, err := runtime.client.Observe(ctx, runtime.taskDigest, runtime.permitDigest)
	if err != nil {
		return err
	}
	status, err = consumeTaskObservation(status, reservation)
	if err != nil {
		return err
	}
	return writeTaskRuntimeStatus(stdout, status)
}

func waitTask(arguments []string, stdout io.Writer) (returnErr error) {
	flags := flag.NewFlagSet("task wait", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "owner-only lifecycle task bundle")
	gatewayURL := flags.String("gateway-url", "", "HTTP literal-loopback Gateway origin")
	tokenPath := flags.String("token-file", "", "owner-only Gateway bearer token")
	resultPath := flags.String("result-out", "", "new owner-only file for a first terminal observation")
	discardResult := flags.Bool("discard-result", false, "discard a first terminal observation after verification")
	waitTimeout := flags.Duration("wait-timeout", 3*time.Minute, "bounded total wait time")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *bundlePath == "" || *gatewayURL == "" || *tokenPath == "" || flags.NArg() != 0 {
		return errors.New("task wait requires -bundle, -gateway-url, and -token-file")
	}
	if (*resultPath != "") == *discardResult {
		return errors.New("task wait requires exactly one of -result-out or -discard-result")
	}
	if *waitTimeout <= 0 || *waitTimeout > maxTaskWait {
		return fmt.Errorf("task wait timeout must be positive and at most %s", maxTaskWait)
	}
	runtime, err := openTaskRuntime(*bundlePath, *gatewayURL, *tokenPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *waitTimeout)
	defer cancel()
	status, err := runtime.client.Status(ctx, runtime.taskDigest, runtime.permitDigest)
	if err != nil {
		return err
	}
	var reservation *taskResultReservation
	defer func() {
		if reservation != nil {
			returnErr = errors.Join(returnErr, reservation.discard())
		}
	}()
	pollInterval := time.Duration(runtime.bundle.Bundle.Operation.PollIntervalSeconds) * time.Second
	observeTerminal := status.Phase == gatewayclient.PhaseTerminal && *resultPath != ""
	for status.Phase != gatewayclient.PhaseTerminal || observeTerminal {
		if status.Phase == gatewayclient.PhaseAuthorize {
			if err := waitTaskPoll(ctx, pollInterval); err != nil {
				return fmt.Errorf("wait for task lifecycle: %w", err)
			}
			status, err = runtime.client.Status(ctx, runtime.taskDigest, runtime.permitDigest)
			if err != nil {
				return err
			}
			continue
		}
		if reservation == nil && *resultPath != "" {
			reservation, err = reserveTaskResult(*resultPath)
			if err != nil {
				return err
			}
		}
		status, err = runtime.client.Observe(ctx, runtime.taskDigest, runtime.permitDigest)
		if err != nil {
			var apiError *gatewayclient.APIError
			if errors.As(err, &apiError) && apiError.RetryAfter > 0 {
				if waitErr := waitTaskPoll(ctx, apiError.RetryAfter); waitErr != nil {
					return fmt.Errorf("wait for task lifecycle: %w", waitErr)
				}
				continue
			}
			return err
		}
		observeTerminal = false
		if status.Phase != gatewayclient.PhaseTerminal {
			if err := waitTaskPoll(ctx, pollInterval); err != nil {
				return fmt.Errorf("wait for task lifecycle: %w", err)
			}
		}
	}
	status, err = consumeTaskObservation(status, reservation)
	if err != nil {
		return err
	}
	if err := writeTaskRuntimeStatus(stdout, status); err != nil {
		return err
	}
	if status.State != string(gatewayclient.AgentReportedCompleted) {
		return fmt.Errorf("task ended in terminal state %s", status.State)
	}
	return nil
}

func openTaskRuntime(bundlePath, gatewayURL, tokenPath string) (taskRuntime, error) {
	bundle, err := readHistoricalLifecycleTaskBundle(bundlePath)
	if err != nil {
		return taskRuntime{}, err
	}
	return openVerifiedTaskRuntime(bundle, gatewayURL, tokenPath)
}

func openCurrentTaskRuntime(bundlePath, gatewayURL, tokenPath string) (taskRuntime, error) {
	bundle, err := readCurrentLifecycleTaskBundle(bundlePath)
	if err != nil {
		return taskRuntime{}, err
	}
	return openVerifiedTaskRuntime(bundle, gatewayURL, tokenPath)
}

func openVerifiedTaskRuntime(bundle verifiedTaskBundle, gatewayURL, tokenPath string) (taskRuntime, error) {
	token, err := nodeclient.ReadToken(tokenPath)
	if err != nil {
		return taskRuntime{}, fmt.Errorf("read Gateway token: %w", err)
	}
	client, err := gatewayclient.New(gatewayURL, token)
	if err != nil {
		return taskRuntime{}, err
	}
	statement := bundle.Verified.Statement
	return taskRuntime{
		bundle: bundle, client: client,
		taskDigest:   taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID),
		permitDigest: bundle.Verified.EnvelopeDigest,
	}, nil
}

func readCurrentLifecycleTaskBundle(path string) (verifiedTaskBundle, error) {
	raw, _, trusted, err := readTaskBundleWithEmbeddedTrust(path)
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	verified, err := decodeTaskBundle(raw, trusted, timeNow().UTC(), taskpermit.MaxValidity)
	if err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("validate current task bundle: %w", err)
	}
	return requireLifecycleTaskBundle(verified)
}

// Historical lifecycle operations authenticate the owner-only bundle at its
// signed start time. Expiry prevents a new dispatch; it must not erase the
// durable identity needed to inspect a task that already ran.
func readHistoricalLifecycleTaskBundle(path string) (verifiedTaskBundle, error) {
	raw, wire, trusted, err := readTaskBundleWithEmbeddedTrust(path)
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	permitRaw, err := decodeCanonicalBase64(wire.Permit, taskpermit.MaxEnvelopeBytes, "task permit")
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	payload, keyID, err := dsse.Verify(permitRaw, taskpermit.PayloadType, trusted)
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	if keyID != wire.Authority.KeyID {
		return verifiedTaskBundle{}, errors.New("task permit key does not match the embedded authority")
	}
	var statement taskpermit.Statement
	if err := dsse.DecodeStrictInto(payload, taskpermit.MaxEnvelopeBytes, &statement); err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("decode signed task permit: %w", err)
	}
	notBefore, err := parsePermitTime(statement.NotBefore)
	if err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("task permit not_before: %w", err)
	}
	verified, err := decodeTaskBundle(raw, trusted, notBefore, taskpermit.MaxValidity)
	if err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("validate historical task bundle: %w", err)
	}
	return requireLifecycleTaskBundle(verified)
}

func readTaskBundleWithEmbeddedTrust(path string) ([]byte, taskBundle, map[string]ed25519.PublicKey, error) {
	raw, err := securefile.Read(path, maxTaskBundleBytes, securefile.OwnerOnly)
	if err != nil {
		return nil, taskBundle{}, nil, fmt.Errorf("read task bundle: %w", err)
	}
	var wire taskBundle
	if err := dsse.DecodeStrictInto(raw, maxTaskBundleBytes, &wire); err != nil {
		return nil, taskBundle{}, nil, fmt.Errorf("decode task bundle: %w", err)
	}
	publicRaw, err := decodeCanonicalBase64(wire.Authority.PublicKey, ed25519.PublicKeySize, "task authority public key")
	if err != nil || len(publicRaw) != ed25519.PublicKeySize {
		return nil, taskBundle{}, nil, errors.New("task bundle authority is not canonical base64 Ed25519")
	}
	public := ed25519.PublicKey(publicRaw)
	trusted := map[string]ed25519.PublicKey{wire.Authority.KeyID: public}
	return raw, wire, trusted, nil
}

func requireLifecycleTaskBundle(verified verifiedTaskBundle) (verifiedTaskBundle, error) {
	if verified.Bundle.SchemaVersion != taskBundleSchemaV2 ||
		verified.Bundle.Operation.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 {
		return verifiedTaskBundle{}, errors.New("task lifecycle commands require a version 2 lifecycle task bundle")
	}
	return verified, nil
}

func waitTaskPoll(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func writeTaskRuntimeStatus(stdout io.Writer, status gatewayclient.TaskLifecycleStatus) error {
	status.ObservationBase64 = ""
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(status)
}

func consumeTaskObservation(
	status gatewayclient.TaskLifecycleStatus,
	reservation *taskResultReservation,
) (gatewayclient.TaskLifecycleStatus, error) {
	encoded := status.ObservationBase64
	status.ObservationBase64 = ""
	if encoded == "" {
		if reservation != nil {
			if err := reservation.discard(); err != nil {
				return gatewayclient.TaskLifecycleStatus{}, err
			}
		}
		return status, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded || int64(len(raw)) != status.ResponseBytes ||
		dsse.Digest(raw) != status.ResultDigest {
		return gatewayclient.TaskLifecycleStatus{}, errors.New("Gateway terminal observation does not match its verified metadata")
	}
	if reservation != nil {
		if err := reservation.commit(raw); err != nil {
			return gatewayclient.TaskLifecycleStatus{}, fmt.Errorf("write terminal observation: %w", err)
		}
	}
	return status, nil
}

type taskResultReservation struct {
	path string
	file *os.File
}

func reserveTaskResult(path string) (*taskResultReservation, error) {
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) && strings.Contains(path, "..") {
		return nil, errors.New("invalid result output path")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	reservation := &taskResultReservation{path: path, file: file}
	if err := syncOutputDirectory(path); err != nil {
		return nil, errors.Join(err, reservation.discard())
	}
	return reservation, nil
}

func (reservation *taskResultReservation) commit(raw []byte) error {
	if reservation == nil || reservation.file == nil {
		return errors.New("terminal result output was not reserved")
	}
	cleanup := func(cause error) error {
		return errors.Join(cause, reservation.discard())
	}
	for written := 0; written < len(raw); {
		count, err := reservation.file.Write(raw[written:])
		if err != nil {
			return cleanup(err)
		}
		if count <= 0 {
			return cleanup(io.ErrShortWrite)
		}
		written += count
	}
	if err := reservation.file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := reservation.file.Close(); err != nil {
		reservation.file = nil
		removeErr := os.Remove(reservation.path)
		return errors.Join(err, removeErr, syncOutputDirectory(reservation.path))
	}
	reservation.file = nil
	if err := syncOutputDirectory(reservation.path); err != nil {
		removeErr := os.Remove(reservation.path)
		return errors.Join(err, removeErr, syncOutputDirectory(reservation.path))
	}
	return nil
}

func (reservation *taskResultReservation) discard() error {
	if reservation == nil || reservation.file == nil {
		return nil
	}
	closeErr := reservation.file.Close()
	reservation.file = nil
	removeErr := os.Remove(reservation.path)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(closeErr, removeErr, syncOutputDirectory(reservation.path))
}
