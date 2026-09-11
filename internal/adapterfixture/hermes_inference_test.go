package adapterfixture

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Exercise the acceptance harness's actual semantic check, independently of the
// signed-ledger verification that precedes it. Synthetic receipts in this unit
// test do not qualify a native runtime; that still requires the disposable host.
func TestHermesAcceptanceRejectsIncorrectInferenceAccounting(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	script := filepath.Join(hermesAdapterRoot(t), "..", "..", "scripts", "hermes-steward-acceptance.sh")
	program := `
import copy
import json
import os
import pathlib
import re
import sys
import tempfile

source = pathlib.Path(sys.argv[1]).read_text()
check = source.split("# BEGIN INFERENCE_ACCOUNTING_CHECK\n", 1)[1].split("# END INFERENCE_ACCOUNTING_CHECK", 1)[0]
summary_check = source.split("# BEGIN INFERENCE_SUMMARY_CHECK\n", 1)[1].split("# END INFERENCE_SUMMARY_CHECK", 1)[0]
admissions = {
    "grant-1": (1, {"runtime_ref": "runtime-1", "policy_digest": "policy-1", "route_policy_digest": "route-1"}),
    "grant-2": (2, {"runtime_ref": "runtime-2", "policy_digest": "policy-2", "route_policy_digest": "route-2"}),
}
receipts = []
issue_by_permit = {f"permit-{i}": ({"request_digest": f"request-{i}"}, 1, f"task-{i}", "run", 1, "result") for i in range(7)}
for index in range(22):
    generation = 1 if index < 19 else 2
    task = index % 4 if index < 15 else (5 + (index - 15) % 2 if index < 19 else 4)
    event = {
        "kind": "inference_attempt", "tenant_id": "tenant", "runtime_ref": f"runtime-{generation}",
        "capsule_digest": "capsule", "policy_digest": f"policy-{generation}",
        "route_policy_digest": f"route-{generation}", "generation": generation,
        "grant_id": f"grant-{generation}", "operation_id": "chat-completions", "connector_id": "",
        "request_bytes": 64, "response_bytes": 0, "task_digest": f"sha256:{index:064x}",
        "phase": "authorize", "outcome": "allowed",
        "inference_task_digest": f"task-{task}", "inference_permit_digest": f"permit-{task}",
        "inference_request_digest": f"request-{task}",
    }
    terminal = dict(event, phase="terminal", outcome="responded", http_status=200)
    for value in (event, terminal):
        receipts.append(("application/vnd.steward.connector-receipt.v10+json", {"event": value}, "unused"))
receipts[31], receipts[32] = receipts[32], receipts[31]  # Both first attempts authorize before either terminates.


def run_case(name, mutate=None, provider_log=b"1\n" * 22, title_log=b"1\n" * 7):
    candidate = copy.deepcopy(receipts)
    if mutate:
        mutate(candidate)
    with tempfile.TemporaryDirectory() as directory:
        work = pathlib.Path(directory)
        scope = dict(os=os, json=json, re=re, work=work, receipts=candidate, admissions=admissions,
                     issue_by_permit=issue_by_permit, overlap_tasks={"task-5", "task-6"},
                     expected_inference_attempts=22, provider_log=provider_log, title_log=title_log,
                     tenant_id="tenant", capsule_digest="capsule")
        try:
            exec(compile(check, sys.argv[1], "exec"), scope)
        except SystemExit:
            if name == "valid":
                raise
            assert not (work / "inference-accounting.json").exists(), name
        else:
            assert name == "valid", f"accepted invalid accounting: {name}"
            result = work / "inference-accounting.json"
            assert result.stat().st_mode & 0o777 == 0o600
            assert json.loads(result.read_text()) == {"authorized_attempts": 22, "provider_requests": 22, "title_requests": 7, "task_scoped": True, "task_count": 7, "concurrent_tasks": 2}
            summary_scope = dict(steps_path=work / "steps", read_small_json=lambda path: json.loads(path.read_text()))
            exec(compile(summary_check, sys.argv[1], "exec"), summary_scope)
            for field in ("task_scoped", "task_count", "authorized_attempts", "provider_requests", "title_requests", "concurrent_tasks"):
                invalid_summary = json.loads(result.read_text())
                del invalid_summary[field]
                summary_scope["read_small_json"] = lambda path: invalid_summary
                try:
                    exec(compile(summary_check, sys.argv[1], "exec"), summary_scope)
                except SystemExit:
                    pass
                else:
                    raise AssertionError(f"summary accepted missing {field}")


run_case("valid")
run_case("missing provider request", provider_log=b"1\n" * 21)
run_case("unexpected provider retry", provider_log=b"1\n" * 23)
run_case("malformed provider counter", provider_log=b"2\n" * 22)
run_case("missing title request", title_log=b"1\n" * 6)
run_case("repeated title request", title_log=b"1\n" * 8)
run_case("malformed title counter", title_log=b"2\n" * 7)
run_case("serialized tasks", lambda items: items.__setitem__(slice(31, 33), [items[32], items[31]]))
run_case("missing terminal", lambda items: items.pop())
run_case("duplicated terminal", lambda items: items.append(copy.deepcopy(items[-1])))
run_case("missing attempt pair", lambda items: items.__delitem__(slice(-2, None)))
run_case("colliding attempt identity", lambda items: items[-1][1]["event"].update(task_digest=items[0][1]["event"]["task_digest"]))
run_case("unknown runtime", lambda items: items[0][1]["event"].update(runtime_ref="other"))
run_case("unknown grant", lambda items: items[0][1]["event"].update(grant_id="other"))
run_case("wrong policy", lambda items: items[0][1]["event"].update(route_policy_digest="other"))
run_case("wrong tenant", lambda items: items[0][1]["event"].update(tenant_id="other"))
run_case("wrong operation", lambda items: items[0][1]["event"].update(operation_id="embeddings"))
run_case("wrong task scope", lambda items: items[0][1]["event"].update(inference_task_digest="other"))
run_case("wrong permit scope", lambda items: items[0][1]["event"].update(inference_permit_digest="other"))
run_case("wrong request scope", lambda items: items[0][1]["event"].update(inference_request_digest="other"))
run_case("runtime-wide receipt", lambda items: items.__setitem__(0, ("application/vnd.steward.connector-receipt.v9+json", items[0][1], "unused")))
run_case("unknown outcome", lambda items: items[1][1]["event"].update(outcome="failed", error_code="outcome_unknown"))
run_case("provider rejection", lambda items: items[1][1]["event"].update(http_status=429))
run_case("response changed size", lambda items: items[1][1]["event"].update(request_bytes=65))
run_case("zero body", lambda items: items[0][1]["event"].update(request_bytes=0))
run_case("unbounded body", lambda items: items[0][1]["event"].update(request_bytes=(1 << 20) + 1))
run_case("reversed phases", lambda items: items.reverse())


def wrong_generation_distribution(items):
    for item in items:
        item[1]["event"].update(generation=1, grant_id="grant-1", runtime_ref="runtime-1",
                               policy_digest="policy-1", route_policy_digest="route-1")


run_case("resume bypassed accounting", wrong_generation_distribution)
`
	command := exec.Command(python, "-I", "-c", program, script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("inference acceptance semantic checks failed: %v\n%s", err, output)
	}
}
