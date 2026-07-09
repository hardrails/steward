package main

import "testing"

func TestEnvOr(t *testing.T) {
	t.Run("unset falls back", func(t *testing.T) {
		if got := envOr("STEWARD_TEST_UNSET", "fallback"); got != "fallback" {
			t.Fatalf("got %q, want fallback", got)
		}
	})
	t.Run("set value wins", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_ADDR", "0.0.0.0:9000")
		if got := envOr("STEWARD_TEST_ADDR", "fallback"); got != "0.0.0.0:9000" {
			t.Fatalf("got %q, want 0.0.0.0:9000", got)
		}
	})
	t.Run("empty value falls back", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_ADDR", "")
		if got := envOr("STEWARD_TEST_ADDR", "fallback"); got != "fallback" {
			t.Fatalf("got %q, want fallback", got)
		}
	})
}

func TestEnvOrInt(t *testing.T) {
	t.Run("unset falls back", func(t *testing.T) {
		if got := envOrInt("STEWARD_TEST_UNSET", 7); got != 7 {
			t.Fatalf("got %d, want 7", got)
		}
	})
	t.Run("valid int wins", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_MAX", "42")
		if got := envOrInt("STEWARD_TEST_MAX", 7); got != 42 {
			t.Fatalf("got %d, want 42", got)
		}
	})
	t.Run("invalid int falls back", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_MAX", "not-a-number")
		if got := envOrInt("STEWARD_TEST_MAX", 7); got != 7 {
			t.Fatalf("got %d, want 7", got)
		}
	})
}
