//go:build qualification

package adapterfixture

import "testing"

// Qualification requires unchanged evidence from the disposable-host harness.
// This test is mandatory in CI and release packaging, but not local development.
func TestHermesQualificationEvidenceBindsCurrentInputs(t *testing.T) {
	verifyHermesQualificationEvidence(t)
}
