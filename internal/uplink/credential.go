// Package uplink is Steward's opt-in outbound control channel. It is a second
// caller of the internal/runtime tracker (not a parallel lifecycle engine): a
// background poll loop dials out to a control plane, executes queued lifecycle
// commands against the tracker, and reports the results. It is enabled only when
// cmd/steward is given an uplink URL, and it adds nothing to the inbound REST
// contract. See docs/uplink-client.md for the design and wire contract.
package uplink

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	credentialVersionTenant = 1
	credentialVersionNode   = 2
)
const maxCredentialBytes = 64 << 10

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
	Scope      string `json:"scope,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	NodeID     string `json:"node_id"`
	Credential string `json:"credential"`
}

// CredentialSecurity is a caller-supplied proof that a node-scoped credential
// will enter only the signed secure Executor path over protected transport. A
// loader cannot infer either property from a filename or bearer token, so both
// are explicit and fail closed. Tenant-scoped v1 credentials do not require
// these fields and retain their existing behavior.
type CredentialSecurity struct {
	SecureExecutor     bool
	ProtectedTransport bool
}

func (c Credential) NodeScoped() bool {
	return c.Version == credentialVersionNode && c.Scope == "node"
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
	return LoadCredentialWithSecurity(path, CredentialSecurity{})
}

// LoadCredentialWithSecurity reads either a tenant-scoped v1 credential or a
// node-scoped v2 credential. Node scope can carry commands for multiple tenants,
// so it is refused unless the caller explicitly attests both secure signed-command
// mode and protected transport. This guard must also be supplied on hot reload.
func LoadCredentialWithSecurity(path string, security CredentialSecurity) (*Credential, error) {
	// A bearer credential is a secret; its file must not be readable or writable
	// by group or others (0600 or stricter). Check the permission bits before
	// reading the contents so an over-exposed secret is a loud, actionable
	// startup error naming the fix, never a silently-accepted world-readable
	// token. The check is on the mode bits themselves, so it fails closed even
	// when the process runs as root (whose access would otherwise bypass the
	// permissions).
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat uplink credential file %q: %w (re-enroll this node and write its credential to that path)", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("uplink credential file %q has insecure permissions %#o: it is readable or writable by group or others; restrict it to the owner (run: chmod 600 %s) so the bearer credential cannot be read by another user", path, perm, path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("uplink credential file %q must be a regular file", path)
	}
	if info.Size() > maxCredentialBytes {
		return nil, fmt.Errorf("uplink credential file %q exceeds the %d-byte limit", path, maxCredentialBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read uplink credential file %q: %w (re-enroll this node and write its credential to that path)", path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened uplink credential file %q: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("uplink credential file %q changed while opening or is not an owner-only regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read uplink credential file %q: %w", path, err)
	}
	if len(raw) == 0 || len(raw) > maxCredentialBytes {
		return nil, fmt.Errorf("uplink credential file %q is empty or exceeds the %d-byte limit", path, maxCredentialBytes)
	}

	var c Credential
	if err := dsse.DecodeStrictInto(raw, maxCredentialBytes, &c); err != nil {
		return nil, fmt.Errorf("uplink credential file %q is not valid credential JSON: %w (re-enroll this node and rewrite the credential file)", path, err)
	}
	switch c.Version {
	case credentialVersionTenant:
		if c.Scope != "" {
			return nil, fmt.Errorf("uplink credential file %q version 1 must not set scope (re-enroll this node and rewrite the credential file)", path)
		}
		if c.TenantID == "" {
			return nil, missingFieldErr(path, "tenant_id")
		}
	case credentialVersionNode:
		if c.Scope != "node" || c.TenantID != "" {
			return nil, fmt.Errorf("uplink credential file %q version 2 must have scope %q and no tenant_id (re-enroll this node and rewrite the credential file)", path, "node")
		}
		if !security.SecureExecutor || !security.ProtectedTransport {
			return nil, fmt.Errorf("uplink credential file %q is node-scoped and requires caller-confirmed secure Executor mode and protected transport", path)
		}
	default:
		return nil, fmt.Errorf("uplink credential file %q has unsupported format version %d; this build reads tenant version %d and node version %d (re-enroll this node and rewrite the credential file)", path, c.Version, credentialVersionTenant, credentialVersionNode)
	}
	switch {
	case c.NodeID == "":
		return nil, missingFieldErr(path, "node_id")
	case c.Credential == "":
		return nil, missingFieldErr(path, "credential")
	}
	if !boundedCredentialIdentity(c.NodeID, 128) ||
		(c.Version == credentialVersionTenant && !boundedCredentialIdentity(c.TenantID, 128)) {
		return nil, fmt.Errorf("uplink credential file %q contains an invalid or oversized tenant_id/node_id", path)
	}
	if len(c.Credential) > 32<<10 || strings.TrimSpace(c.Credential) == "" || strings.ContainsAny(c.Credential, "\r\n\x00") {
		return nil, fmt.Errorf("uplink credential file %q contains an invalid or oversized bearer credential", path)
	}
	return &c, nil
}

func boundedCredentialIdentity(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
}

// missingFieldErr builds a uniform fail-closed error for a credential file that is
// well-formed JSON of the right version but missing a required field, always
// naming the path and the remedy so the message passes the 3am test.
func missingFieldErr(path, field string) error {
	return fmt.Errorf("uplink credential file %q is missing a non-empty %s (re-enroll this node and rewrite the credential file)", path, field)
}
