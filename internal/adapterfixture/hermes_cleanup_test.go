package adapterfixture

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHermesCleanupRemovesReadonlyStateWithoutFollowingLinks(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		t.Skip("requires the unprivileged Linux qualification runner and GNU tools")
	}
	root := hermesAdapterRoot(t)
	source := string(readBounded(t, filepath.Join(root, "../../scripts/hermes-feasibility.sh"), 2<<20))
	functions := ""
	for _, name := range []string{"bounded_state_root", "remove_state_root"} {
		start := strings.Index(source, name+"() {\n")
		if start < 0 {
			t.Fatalf("missing cleanup function %s", name)
		}
		end := strings.Index(source[start:], "\n}\n")
		if end < 0 {
			t.Fatalf("unterminated cleanup function %s", name)
		}
		functions += source[start:start+end+3] + "\n"
	}
	// Exercise the real cleanup functions as the current unprivileged owner;
	// the privilege-wrapper contract is checked separately. Everything created
	// here is synthetic and confined to fresh, explicitly named temporary roots.
	code := `set -euo pipefail
work=$(mktemp -d /tmp/steward-hermes-feasibility.XXXXXX)
state_root=$(mktemp -d /tmp/steward-hermes-state.XXXXXX)
outside=$(mktemp -d /tmp/steward-hermes-cleanup-test.XXXXXX)
readonly work outside
trap 'chmod u+rwx -- "$outside"; rm -rf -- "$work" "$state_root" "$outside"' EXIT
state_owner_command() { "$@"; }
` + functions + `
mkdir -p "$state_root/skills/example/nested"
printf 'skill\n' >"$state_root/skills/example/nested/SKILL.md"
printf 'keep\n' >"$outside/sentinel"
ln -s "$outside" "$state_root/skills/outside"
chmod 0555 "$outside" "$state_root/skills/example" "$state_root/skills/example/nested"
chmod 0444 "$state_root/skills/example/nested/SKILL.md"
remove_state_root
test ! -e "$state_root"
test "$(cat "$outside/sentinel")" = keep
test "$(stat -c %a "$outside")" = 555

# Even an absent path must not cause a cleanup outside the exact state scope.
(state_root="$outside"; remove_state_root) && exit 1
test -f "$outside/sentinel"
`
	output, err := exec.Command("bash", "-c", code).CombinedOutput()
	if err != nil {
		t.Fatalf("bounded readonly-state cleanup failed: %v\n%s", err, output)
	}
}
