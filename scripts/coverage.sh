#!/usr/bin/env bash
# Honest aggregate-coverage gate for Steward. Fails (exit 1) when the unioned
# statement coverage across every package is below the floor (default 0.85).
#
# Why this is not just `go test -coverprofile`: main() is genuinely exercised by
# the subprocess integration tests in cmd/steward/main_test.go — they build the
# real binary and drive its startup, uplink wiring, and graceful shutdown. But a
# plain `go build` binary is not coverage-instrumented, so `go test -cover`
# reports main() at 0% even though those tests run it end to end. That is a
# MEASUREMENT gap, not a test gap. This script closes it with the standard Go
# integration-coverage flow (go build -cover + GOCOVERDIR + go tool covdata):
#
#   1. One `go test` run writes the unit profile via -coverprofile, and — because
#      STEWARD_TEST_COVERDIR is set — the cmd/steward integration tests build a
#      -cover binary whose counters land in a dedicated dir (GOCOVERDIR is
#      injected per-subprocess by stewardEnv in main_test.go). The dir is
#      dedicated on purpose: it keeps `covdata`'s input a clean single-meta set
#      (just the standalone binary's own counters) instead of mixing in the
#      go-test test-binary's separate coverage pods, so step 2 below has one
#      unambiguous source to convert.
#      `cmd/steward-executor` does the same into a second directory so the two
#      binaries' distinct coverage metadata never mix.
#   2. `go tool covdata textfmt` turns each standalone binary's counters into a
#      text profile.
#   3. The four profiles are unioned: a source region counts as covered if the
#      unit tests or any integration binary covered it. All instrument the
#      same package set (-coverpkg=./...), so the union is honest, not double-counting.
#
# Usage: scripts/coverage.sh [min-fraction]   (default 0.85)
# Env:   COVERAGE_OUT   path for the merged profile (default ./coverage.out)
set -euo pipefail

min="${1:-0.85}"
out="${COVERAGE_OUT:-coverage.out}"

covdir="$(mktemp -d)"
executor_covdir="$(mktemp -d)"
control_covdir="$(mktemp -d)"
unit="$(mktemp)"
integration="$(mktemp)"
executor_integration="$(mktemp)"
control_integration="$(mktemp)"
trap 'rm -rf "$covdir" "$executor_covdir" "$control_covdir" "$unit" "$integration" "$executor_integration" "$control_integration"' EXIT

# -count=1 forces a real test run (no cache): a cached run would not re-execute
# the integration subprocess, leaving no coverage data in $covdir.
STEWARD_TEST_COVERDIR="$covdir" \
	STEWARD_EXECUTOR_TEST_COVERDIR="$executor_covdir" \
	STEWARD_CONTROL_TEST_COVERDIR="$control_covdir" \
	go test -count=1 -coverpkg=./... -coverprofile="$unit" ./...

if ! ls "$covdir"/covmeta.* >/dev/null 2>&1; then
	echo "coverage: no integration coverage data written to $covdir" >&2
	echo "  (the cmd/steward subprocess tests should build a -cover binary; see main_test.go)" >&2
	exit 1
fi
go tool covdata textfmt -i="$covdir" -o="$integration"

if ! ls "$executor_covdir"/covmeta.* >/dev/null 2>&1; then
	echo "coverage: no Executor integration coverage data written to $executor_covdir" >&2
	exit 1
fi
go tool covdata textfmt -i="$executor_covdir" -o="$executor_integration"

if ! ls "$control_covdir"/covmeta.* >/dev/null 2>&1; then
	echo "coverage: no Steward Control integration coverage data written to $control_covdir" >&2
	exit 1
fi
go tool covdata textfmt -i="$control_covdir" -o="$control_integration"

# Union the unit and integration profiles. Region key is the source span
# (field 1); the statement count is field 2; field 3 is the hit count.
awk 'FNR==1 { next }
	{ k=$1; if (!(k in seen)) { seen[k]=1; order[++n]=k; stmts[k]=$2 }
	  if ($3+0 > 0) cov[k]=1 }
	END { print "mode: set"
	      for (i=1; i<=n; i++) { k=order[i]; print k, stmts[k], (k in cov)?1:0 } }' \
	"$unit" "$integration" "$executor_integration" "$control_integration" >"$out"

read -r covered statements < <(awk 'NR > 1 { statements += $2; if ($3+0 > 0) covered += $2 }
	END { print covered+0, statements+0 }' "$out")
total="$(awk -v c="$covered" -v s="$statements" 'BEGIN { printf "%.4f", 100*c/s }')"
floor="$(awk -v m="$min" 'BEGIN { printf "%.4f", m*100 }')"
echo "coverage: aggregate ${total}% (floor ${floor}%)"

if awk -v c="$covered" -v s="$statements" -v m="$min" 'BEGIN { exit (c/s + 1e-12 < m) ? 0 : 1 }'; then
	echo "coverage: FAIL — ${total}% is below the ${floor}% floor" >&2
	exit 1
fi
echo "coverage: OK — profile written to ${out}"
