package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestActivationCommandDispatchAndGeneratedID(t *testing.T) {
	for _, command := range []string{
		"create",
		"attach",
		"run",
		"status",
		"verify",
	} {
		t.Run(command, func(t *testing.T) {
			if err := activationCommand(
				[]string{command}, &bytes.Buffer{},
			); err == nil {
				t.Fatal("incomplete activation command unexpectedly succeeded")
			}
		})
	}
	for _, arguments := range [][]string{nil, {"unknown"}} {
		if err := activationCommand(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid activation arguments %q unexpectedly succeeded", arguments)
		}
	}

	first, err := randomActivationID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomActivationID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second ||
		!strings.HasPrefix(first, "activation-") ||
		len(first) != len("activation-")+32 {
		t.Fatalf("generated activation IDs %q and %q", first, second)
	}
}

func TestActivationTimeoutValidationAndErrorMessages(t *testing.T) {
	valid := []time.Duration{
		time.Second,
		2 * time.Second,
		3 * time.Second,
		4 * time.Second,
		5 * time.Second,
		24 * time.Hour,
	}
	if got, err := activationTimeouts(valid...); err != nil ||
		got.PreflightSeconds != 1 ||
		got.EvidenceSeconds != 24*60*60 {
		t.Fatalf("timeouts=%#v err=%v", got, err)
	}
	for _, values := range [][]time.Duration{
		valid[:5],
		{0, time.Second, time.Second, time.Second, time.Second, time.Second},
		{time.Second + time.Nanosecond, time.Second, time.Second, time.Second, time.Second, time.Second},
		{25 * time.Hour, time.Second, time.Second, time.Second, time.Second, time.Second},
	} {
		if _, err := activationTimeouts(values...); err == nil {
			t.Fatalf("invalid timeout values %v accepted", values)
		}
	}

	cause := errors.New("sentinel")
	errorsUnderTest := []struct {
		err      error
		contains string
		unwrap   bool
	}{
		{
			err:      &activationArtifactConflictError{name: "result.json"},
			contains: "already exists with different bytes",
		},
		{
			err:      &activationCanaryTerminalError{state: "failed"},
			contains: "terminal state failed",
		},
		{
			err: &activationCanaryTerminalError{
				state: "failed",
				code:  "agent_error",
			},
			contains: "(agent_error)",
		},
		{
			err:      &activationCanaryRetainedInvalidError{cause: cause},
			contains: "retained canary state is invalid",
			unwrap:   true,
		},
		{
			err:      &activationCanaryAuthorizationInvalidError{cause: cause},
			contains: "canary authorization is not currently valid",
			unwrap:   true,
		},
		{
			err: &activationCanaryTimeoutError{
				deadline: time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC),
			},
			contains: "2026-07-16T10:00:00Z",
		},
		{
			err:      &activationRetainedEvidenceInvalidError{cause: cause},
			contains: "retained activation evidence is invalid",
			unwrap:   true,
		},
	}
	for _, test := range errorsUnderTest {
		if !strings.Contains(test.err.Error(), test.contains) {
			t.Fatalf("error %q does not contain %q", test.err, test.contains)
		}
		if test.unwrap && !errors.Is(test.err, cause) {
			t.Fatalf("error %q does not unwrap the cause", test.err)
		}
	}
}
