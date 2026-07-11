package buildinfo

import "testing"

func TestResolvePrefersStampedReleaseVersion(t *testing.T) {
	previous := releaseVersion
	releaseVersion = "v9.8.7-test.1"
	t.Cleanup(func() { releaseVersion = previous })

	if got := Resolve(); got != releaseVersion {
		t.Fatalf("Resolve() = %q, want stamped release version %q", got, releaseVersion)
	}
}
