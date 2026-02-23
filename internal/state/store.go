package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	path string
	mu   sync.RWMutex
	snap Snapshot
}

func New(path string) (*Store, error) {
	s := &Store{
		path: path,
		snap: Snapshot{Instances: map[string]InstanceRecord{}, UpdatedAt: time.Now().UTC()},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Get(id string) (InstanceRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.snap.Instances[id]
	return r, ok
}

func (s *Store) List() []InstanceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]InstanceRecord, 0, len(s.snap.Instances))
	for _, v := range s.snap.Instances {
		out = append(out, v)
	}
	return out
}

func (s *Store) Upsert(rec InstanceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.UpdatedAt = time.Now().UTC()
	s.snap.Instances[rec.InstanceID] = rec
	s.snap.UpdatedAt = rec.UpdatedAt
	return s.persistLocked()
}

func (s *Store) MarkStopped(instanceID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.snap.Instances[instanceID]
	if !ok {
		return nil
	}
	rec.Status = "stopped"
	rec.LastError = reason
	rec.UpdatedAt = time.Now().UTC()
	s.snap.Instances[instanceID] = rec
	s.snap.UpdatedAt = rec.UpdatedAt
	return s.persistLocked()
}

func (s *Store) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, v := range s.snap.Instances {
		switch v.Status {
		case "starting", "running", "stopping":
			count++
		}
	}
	return count
}

func (s *Store) load() error {
	if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read state file: %w", err)
	}
	if len(b) == 0 {
		return nil
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if snap.Instances == nil {
		snap.Instances = map[string]InstanceRecord{}
	}
	s.snap = snap
	return nil
}

func (s *Store) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	b, err := json.MarshalIndent(s.snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}
