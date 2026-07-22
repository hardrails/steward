// Package buildinfo resolves the version shared by every Steward process binary.
package buildinfo

import "runtime/debug"

// Version is the fallback used when the Go toolchain supplies no module or VCS
// metadata (notably go run and go test).
const Version = "2.9.0"

// releaseVersion is set only by scripts/release.sh through the standard Go
// linker's -X flag. A checkout build's module version is normally "(devel)" and
// VCS metadata identifies a commit, not the release tag, so a published archive
// must carry the tag explicitly. Developer builds leave this empty.
var releaseVersion string

// Resolve prefers an explicit release stamp, then the tagged module version, the
// shortened VCS revision, and finally Version. Every Steward binary calls this
// function so a release cannot report different provenance strings.
func Resolve() string {
	if releaseVersion != "" {
		return releaseVersion
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Version
	}
	if version := info.Main.Version; version != "" && version != "(devel)" {
		return version
	}
	var revision string
	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return Version
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "-dirty"
	}
	return revision
}
