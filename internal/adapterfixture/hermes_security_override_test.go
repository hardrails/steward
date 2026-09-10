package adapterfixture

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHermesSecurityOverridesBindTheReplacedLockAndWheelIdentity(t *testing.T) {
	root := hermesAdapterRoot(t)
	builder := string(readBounded(t, filepath.Join(root, "../../scripts/build-hermes-adapter.sh"), 2<<20))
	const begin = "# BEGIN HERMES_SECURITY_OVERRIDES\n"
	const end = "# END HERMES_SECURITY_OVERRIDES"
	if strings.Count(builder, begin) != 1 || strings.Count(builder, end) != 1 {
		t.Fatal("security override validation must have one extractable block")
	}
	block := strings.Split(strings.Split(builder, begin)[1], end)[0]
	block = strings.ReplaceAll(block, `pathlib.Path("/input/adapter/adapter.json")`, `pathlib.Path(sys.argv[2])`)
	code := "import json,pathlib,re,sys\nlock=json.loads(sys.argv[1])\n" + block + "\nprint(json.dumps(additional_packages))\n"
	var adapter map[string]any
	decodeEvidence(t, filepath.Join(root, "adapter.json"), &adapter)
	encoded, err := json.Marshal(adapter)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"valid", "upstream-drift", "missing-package", "duplicate", "wrong-wheel", "unknown-field", "too-many", "unbounded-name"} {
		t.Run(name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			overrides := document["security_overrides"].([]any)
			if len(overrides) != 2 {
				t.Fatal("review the narrow two-package exception when its inventory changes")
			}
			first := overrides[0].(map[string]any)
			lock := map[string]any{"package": []any{
				map[string]any{"name": "httpcore2", "version": "2.7.0"},
				map[string]any{"name": "httpx2", "version": "2.7.0"},
			}}
			switch name {
			case "upstream-drift":
				first["replaces"] = "2.8.0"
			case "missing-package":
				lock["package"] = []any{}
			case "duplicate":
				document["security_overrides"] = append(overrides, first)
			case "wrong-wheel":
				first["wheel"].(map[string]any)["url"] = "https://files.pythonhosted.org/packages/wrong-2.12.0-py3-none-any.whl"
			case "unknown-field":
				first["command"] = "unexpected"
			case "too-many":
				document["security_overrides"] = make([]any, 9)
			case "unbounded-name":
				first["name"] = "httpcore2\n--index-url=unexpected"
			}
			content, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "adapter.json")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			lockBytes, err := json.Marshal(lock)
			if err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("python3", "-I", "-c", code, string(lockBytes), path).CombinedOutput()
			if name == "valid" {
				if err != nil {
					t.Fatalf("valid exact overrides rejected: %v\n%s", err, output)
				}
				var packages []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}
				if err := json.Unmarshal(output, &packages); err != nil || len(packages) != 2 || packages[0].Name != "httpcore2" || packages[1].Name != "httpx2" || packages[0].Version != "2.12.0" || packages[1].Version != "2.12.0" {
					t.Fatalf("unexpected override plan: %s (%v)", output, err)
				}
			} else if err == nil {
				t.Fatalf("unsafe override accepted: %s", output)
			}
		})
	}
}
