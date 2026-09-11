package connectorledger

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestReleaseChecksMatchConnectorReceiptWriters(t *testing.T) {
	declaration := regexp.MustCompile(`"connector_receipt_log": \{"read_min": [0-9]+, "read_max": [0-9]+, "write": [0-9]+\}`)
	want := `"connector_receipt_log": {"read_min": 1, "read_max": 9, "write": 9}`
	for _, path := range []string{
		"scripts/write-release-manifest.sh",
		"scripts/install-node.sh",
		"scripts/activate-node-release.sh",
		".github/workflows/ci.yml",
		".github/workflows/release.yml",
	} {
		t.Run(path, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", path))
			if err != nil {
				t.Fatal(err)
			}
			matches := declaration.FindAllString(string(raw), -1)
			if len(matches) != 1 || matches[0] != want {
				t.Fatalf("receipt writer/check must declare the supported format once: %v", matches)
			}
		})
	}
}
