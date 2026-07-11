package executoruplink

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const stateVersion = 1
const maxStateBytes = 1 << 20

type position struct {
	Generation     int64  `json:"generation"`
	Sequence       int64  `json:"sequence"`
	ReportedStatus string `json:"reported_status"`
	Absent         bool   `json:"absent,omitempty"`
}

type stateFile struct {
	Version   int                 `json:"version"`
	Positions map[string]position `json:"positions"`
}

// StateStore durably fences stale lifecycle commands across executor restarts.
// One store belongs to one enrolled node; keys are tenant-scoped instance ids.
type StateStore struct {
	mu        sync.Mutex
	path      string
	positions map[string]position
}

func LoadStateStore(path string) (*StateStore, error) {
	if path == "" {
		return nil, errors.New("uplink state file is required")
	}
	store := &StateStore{path: path, positions: make(map[string]position)}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("uplink state %q is missing; initialize a newly enrolled node once with -initialize-uplink-state before starting the executor", path)
	}
	if err != nil {
		return nil, fmt.Errorf("stat uplink state %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("uplink state %q must be a regular file with mode 0600 or stricter", path)
	}
	if info.Size() > maxStateBytes {
		return nil, fmt.Errorf("uplink state %q exceeds %d bytes", path, maxStateBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open uplink state %q: %w", path, err)
	}
	defer f.Close()
	var state stateFile
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("decode uplink state %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("uplink state %q must contain exactly one JSON object", path)
	}
	if state.Version != stateVersion || state.Positions == nil {
		return nil, fmt.Errorf("uplink state %q has unsupported or incomplete format", path)
	}
	for instanceID, value := range state.Positions {
		if instanceID == "" || value.Generation <= 0 || value.Sequence <= 0 || value.ReportedStatus == "" {
			return nil, fmt.Errorf("uplink state %q contains an invalid position", path)
		}
	}
	store.positions = state.Positions
	return store, nil
}

// InitializeStateStore creates the empty fence for a newly enrolled executor.
// It is deliberately exclusive: it never overwrites an existing file, and normal
// startup never recreates a missing file, so losing durable fence state is a loud
// failure rather than permission to replay an old command against a new workload.
func InitializeStateStore(path string) error {
	if path == "" {
		return errors.New("uplink state file is required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("initialize uplink state %q: %w", path, err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := json.NewEncoder(file).Encode(stateFile{
		Version: stateVersion, Positions: map[string]position{},
	}); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

func (s *StateStore) position(instanceID string) (position, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.positions[instanceID]
	return value, ok
}

func (s *StateStore) advance(instanceID string, value position) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.positions[instanceID]
	if ok && (value.Generation < current.Generation ||
		(value.Generation == current.Generation && value.Sequence < current.Sequence)) {
		return errors.New("refusing to move uplink state backwards")
	}
	next := make(map[string]position, len(s.positions)+1)
	for key, existing := range s.positions {
		next[key] = existing
	}
	next[instanceID] = value
	if err := s.persist(next); err != nil {
		return err
	}
	s.positions = next
	return nil
}

func (s *StateStore) persist(positions map[string]position) error {
	dir := filepath.Dir(s.path)
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(stateFile{Version: stateVersion, Positions: positions}); err != nil {
		return err
	}
	if encoded.Len() > maxStateBytes {
		return fmt.Errorf("uplink state would exceed %d bytes", maxStateBytes)
	}
	tmp, err := os.CreateTemp(dir, ".steward-executor-state-*")
	if err != nil {
		return fmt.Errorf("create temporary uplink state: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(encoded.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace uplink state %q: %w", s.path, err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open uplink state directory %q: %w", dir, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync uplink state directory %q: %w", dir, err)
	}
	return nil
}
