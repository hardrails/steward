package gateway

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxAuditBytes = int64(64 << 20)

type EgressStats struct {
	Allowed         uint64 `json:"allowed"`
	Denied          uint64 `json:"denied"`
	BytesFromAgent  uint64 `json:"bytes_from_agent"`
	BytesToAgent    uint64 `json:"bytes_to_agent"`
	LastDestination string `json:"last_destination,omitempty"`
	LastDecision    string `json:"last_decision,omitempty"`
	LastObservedAt  string `json:"last_observed_at,omitempty"`
}

type egressAuditEvent struct {
	Timestamp      string `json:"timestamp"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	GrantID        string `json:"grant_id"`
	TenantID       string `json:"tenant_id"`
	InstanceID     string `json:"instance_id"`
	RouteID        string `json:"route_id,omitempty"`
	Method         string `json:"method"`
	Host           string `json:"host,omitempty"`
	Port           int    `json:"port,omitempty"`
	BytesFromAgent int64  `json:"bytes_from_agent,omitempty"`
	BytesToAgent   int64  `json:"bytes_to_agent,omitempty"`
}

type auditLog struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	disabled bool
}

func openAuditLog(path string, required bool) (*auditLog, error) {
	if !required {
		return &auditLog{disabled: true}, nil
	}
	if !absoluteClean(path) {
		return nil, errors.New("egress audit file must be an absolute clean path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxAuditBytes {
			return nil, errors.New("egress audit file must be a bounded owner-only regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &auditLog{path: path, file: file}, nil
}

func (a *auditLog) Append(event egressAuditEvent) error {
	if a == nil || a.disabled {
		return nil
	}
	event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	info, err := a.file.Stat()
	if err != nil {
		return err
	}
	if info.Size()+int64(len(raw)) > maxAuditBytes {
		if err := a.rotateLocked(); err != nil {
			return err
		}
	}
	if _, err := a.file.Write(raw); err != nil {
		return err
	}
	return a.file.Sync()
}

func (a *auditLog) rotateLocked() error {
	if err := a.file.Sync(); err != nil {
		return err
	}
	if err := a.file.Close(); err != nil {
		return err
	}
	_ = os.Remove(a.path + ".1")
	if err := os.Rename(a.path, a.path+".1"); err != nil {
		return err
	}
	file, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	a.file = file
	return nil
}

func (a *auditLog) Close() error {
	if a == nil || a.disabled {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	return err
}
