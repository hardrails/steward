// Package buildinfo resolves the version shared by every Steward process binary.
package buildinfo

import "runtime/debug"

// Version is the fallback used when the Go toolchain supplies no module or VCS
// metadata (notably go run and go test).
const Version = "0.1.0"

// Resolve prefers the tagged module version, then the shortened VCS revision,
// and finally Version. Both steward and steward-executor call this one function
// so a release can never report two different provenance strings.
func Resolve() string {
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
