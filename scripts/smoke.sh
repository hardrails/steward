#!/usr/bin/env bash
# Smoke test: build the real steward binary, run it on a real port, assert the
# liveness contract (GET /v1/healthz -> 200 {"status":"ok"}), then SIGTERM it and
# assert a clean, panic-free exit within a timeout. Dependency-free — curl and the
# shell only — matching Steward's stdlib-only ethos. This is the release
# happy-path an operator sees on `go run ./cmd/steward` + a probe, exercised end
# to end rather than through the Go test harness.
#
# Usage: scripts/smoke.sh [host:port]   (default 127.0.0.1:8080)
set -euo pipefail

addr="${1:-127.0.0.1:8080}"
url="http://${addr}/v1/healthz"

workdir="$(mktemp -d)"
bin="${workdir}/steward"
log="${workdir}/steward.log"

pid=""
cleanup() {
	[ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null && kill -KILL "${pid}" 2>/dev/null || true
	rm -rf "${workdir}"
}
trap cleanup EXIT

echo "smoke: building steward"
go build -o "${bin}" ./cmd/steward

echo "smoke: starting steward on ${addr}"
"${bin}" -addr "${addr}" >"${log}" 2>&1 &
pid=$!

# Wait up to ~5s for the listener to accept and serve; fail fast if it dies.
body=""
for _ in $(seq 1 50); do
	if body="$(curl -fsS "${url}" 2>/dev/null)"; then break; fi
	if ! kill -0 "${pid}" 2>/dev/null; then
		echo "smoke: steward exited during startup" >&2
		cat "${log}" >&2
		exit 1
	fi
	body=""
	sleep 0.1
done
if [ -z "${body}" ]; then
	echo "smoke: /v1/healthz never became ready within timeout" >&2
	cat "${log}" >&2
	exit 1
fi

# Assert the HTTP status and the body shape explicitly.
code="$(curl -s -o /dev/null -w '%{http_code}' "${url}")"
if [ "${code}" != "200" ]; then
	echo "smoke: expected HTTP 200 from ${url}, got ${code}" >&2
	cat "${log}" >&2
	exit 1
fi
case "${body}" in
*'"status"'*'"ok"'*) : ;;
*)
	echo "smoke: unexpected /v1/healthz body: ${body}" >&2
	exit 1
	;;
esac
echo "smoke: healthz OK — 200 ${body}"

echo "smoke: sending SIGTERM"
kill -TERM "${pid}"

# Assert a clean exit within ~10s.
exit_code=""
for _ in $(seq 1 100); do
	if ! kill -0 "${pid}" 2>/dev/null; then
		wait "${pid}"
		exit_code=$?
		break
	fi
	sleep 0.1
done
if [ -z "${exit_code}" ]; then
	echo "smoke: steward did not exit within timeout after SIGTERM" >&2
	cat "${log}" >&2
	exit 1
fi
if [ "${exit_code}" != "0" ]; then
	echo "smoke: expected a clean exit 0 after SIGTERM, got ${exit_code}" >&2
	cat "${log}" >&2
	exit 1
fi
if grep -qi 'panic' "${log}"; then
	echo "smoke: panic detected in steward output" >&2
	cat "${log}" >&2
	exit 1
fi

echo "smoke: OK — /v1/healthz served 200 and the process shut down cleanly (exit 0)"
