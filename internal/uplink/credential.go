// Package uplink is Steward's opt-in outbound control channel. It is a second
// caller of the internal/runtime tracker (not a parallel lifecycle engine): a
// background poll loop dials out to a control plane, executes queued lifecycle
// commands against the tracker, and reports the results. It is enabled only when
// cmd/steward is given an uplink URL, and it adds nothing to the inbound REST
// contract. See docs/uplink-client.md for the design and wire contract.
package uplink

import (
	"encoding/json"
	"fmt"
	"os"
)

// credentialVersion is the on-disk format version of the credential file. It is
// checked on load so a future incompatible format change fails closed rather than
// being silently mis-parsed, mirroring the tracker's state-file versioning.
const credentialVersion = 1

// Credential is the operator-provisioned bearer identity a node presents on every
// outbound poll and report. It is the output of control-plane enrollment, dropped
// on the node as a small, versioned JSON file:
//
//	{"version":1,"tenant_id":"acme","node_id":"node-7","credential":"<opaque token>"}
//
// The credential is one opaque string, sent verbatim in the Authorization header;
// Steward never parses it and does not reimplement the control plane's credential
// codec. tenant_id and node_id are stored as separate explicit fields (not
// extracted from the token) because the client needs node_id locally — to verify
// each command is addressed to this node, and for logging — without depending on
// the token's internal format.
type Credential struct {
	Version    int    `json:"version"`
	TenantID   string `json:"tenant_id"`
	NodeID     string `json:"node_id"`
	Credential string `json:"credential"`
}

// LoadCredential reads and validates the credential file at path, fail-closed. It
// is called only when the uplink is enabled, so — unlike runtime.LoadTracker's
// optional state file — a missing file is a fatal error, not a first-run empty
// start: an enabled uplink with no credential cannot authenticate. A missing,
// unreadable, over-permissive, non-JSON, wrong-version, or empty-field file
// returns an error whose message names the path and the remedy (re-enroll the
// node and rewrite the file), never a silently-disabled uplink. On success it
// returns the parsed credential.
//
// It runs on every load — startup, -check-config, and the credential hot-reload
// watch (see Poller.waitForCredentialChange) — so an over-permissive credential
// is refused on every path a new credential can enter, not just at boot.
func LoadCredential(path string) (*Credential, error) {
	// A bearer credential is a secret; its file must not be readable or writable
	// by group or others (0600 or stricter). Check the permission bits before
	// reading the contents so an over-exposed secret is a loud, actionable
	// startup error naming the fix, never a silently-accepted world-readable
	// token. The check is on the mode bits themselves, so it fails closed even
	// when the process runs as root (whose access would otherwise bypass the
	// permissions).
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat uplink credential file %q: %w (re-enroll this node and write its credential to that path)", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("uplink credential file %q has insecure permissions %#o: it is readable or writable by group or others; restrict it to the owner (run: chmod 600 %s) so the bearer credential cannot be read by another user", path, perm, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read uplink credential file %q: %w (re-enroll this node and write its credential to that path)", path, err)
	}

	var c Credential
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("uplink credential file %q is not valid credential JSON: %w (re-enroll this node and rewrite the credential file)", path, err)
	}
	if c.Version != credentialVersion {
		return nil, fmt.Errorf("uplink credential file %q has unsupported format version %d; this build reads version %d (re-enroll this node and rewrite the credential file)", path, c.Version, credentialVersion)
	}
	switch {
	case c.TenantID == "":
		return nil, missingFieldErr(path, "tenant_id")
	case c.NodeID == "":
		return nil, missingFieldErr(path, "node_id")
	case c.Credential == "":
		return nil, missingFieldErr(path, "credential")
	}
	return &c, nil
}

// missingFieldErr builds a uniform fail-closed error for a credential file that is
// well-formed JSON of the right version but missing a required field, always
// naming the path and the remedy so the message passes the 3am test.
func missingFieldErr(path, field string) error {
	return fmt.Errorf("uplink credential file %q is missing a non-empty %s (re-enroll this node and rewrite the credential file)", path, field)
}
