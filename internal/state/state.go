// Package state tracks whether the game directory is currently clean or has a
// modded session deployed into it.
//
// The important case this exists for is the ungraceful one. If a modded session
// is interrupted — the game hard-crashes, the machine loses power, the guard is
// killed from Task Manager — then mod files are sitting in the game directory
// with nothing scheduled to remove them. Without a durable marker, the next
// launch would look at a modded directory with no idea it was mid-session.
//
// So the marker is written *before* the mod is deployed and cleared *after* it
// is swept back. Any launch that finds it set knows a previous session did not
// finish, and forces a sweep before doing anything else. Crashing therefore
// fails safe.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Mode describes what the game directory is supposed to contain.
type Mode string

const (
	// Clean means no mod artifacts are deployed.
	Clean Mode = "clean"
	// Modded means a modded session is in progress and artifacts are deployed.
	Modded Mode = "modded"
)

// State is the durable record, stored next to the vault.
type State struct {
	Mode Mode `json:"mode"`
	// SessionStartedAt is when the current modded session began. Zero when clean.
	SessionStartedAt time.Time `json:"session_started_at,omitzero"`
	// SessionPID is the guard process that owns the modded session, recorded so
	// `status` can report whether that process is still alive.
	SessionPID int `json:"session_pid,omitempty"`
	// FirewallRuleActive records that a modded session installed the outbound
	// block, so cleanup can remove it even after a crash.
	FirewallRuleActive bool `json:"firewall_rule_active,omitempty"`
	// LastCleanAt is when the directory was last verified clean.
	LastCleanAt time.Time `json:"last_clean_at,omitzero"`
}

// Store persists State to a file.
type Store struct {
	Path string
}

// NewStore returns a Store backed by path.
func NewStore(path string) *Store { return &Store{Path: path} }

// Load reads the state, returning a clean default if no file exists yet.
//
// A corrupt state file is treated as "modded", not "clean". If the record of
// what the directory contains is unreadable, the safe assumption is the one
// that triggers a sweep.
func (s *Store) Load() (*State, error) {
	data, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return &State{Mode: Clean}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return &State{Mode: Modded}, nil
	}
	if st.Mode != Clean && st.Mode != Modded {
		return &State{Mode: Modded}, nil
	}
	return &st, nil
}

// Save writes the state durably.
//
// The write goes to a temporary file that is fsynced before being renamed into
// place, because a state file that is torn by a power cut is precisely the
// situation this package exists to survive.
func (s *Store) Save(st *State) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// BeginModdedSession marks the directory as modded before any mod file is
// written to it.
func (s *Store) BeginModdedSession(pid int, firewallActive bool) error {
	return s.Save(&State{
		Mode:               Modded,
		SessionStartedAt:   time.Now().UTC(),
		SessionPID:         pid,
		FirewallRuleActive: firewallActive,
	})
}

// MarkClean records that the directory has been verified clean.
func (s *Store) MarkClean() error {
	return s.Save(&State{Mode: Clean, LastCleanAt: time.Now().UTC()})
}

// NeedsRecovery reports whether a previous modded session failed to clean up.
func (st *State) NeedsRecovery() bool { return st.Mode == Modded }
