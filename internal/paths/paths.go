// Package paths resolves where SF6Guard keeps its own data.
package paths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Layout is the set of locations SF6Guard uses.
type Layout struct {
	// Root is the per-user data directory (%LOCALAPPDATA%\SF6Guard on Windows).
	Root string
}

// Discover returns the layout for the current user.
func Discover() (*Layout, error) {
	if override := os.Getenv("SF6GUARD_HOME"); override != "" {
		return &Layout{Root: override}, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locating user config directory: %w", err)
	}
	return &Layout{Root: filepath.Join(base, "SF6Guard")}, nil
}

func (l *Layout) ConfigPath() string   { return filepath.Join(l.Root, "config.json") }
func (l *Layout) ManifestPath() string { return filepath.Join(l.Root, "clean-manifest.json") }
func (l *Layout) StatePath() string    { return filepath.Join(l.Root, "state.json") }
func (l *Layout) VaultDir() string     { return filepath.Join(l.Root, "vault") }
func (l *Layout) KeyPath() string      { return filepath.Join(l.Root, "token.key") }
func (l *Layout) TokenPath() string    { return filepath.Join(l.Root, "intent.tok") }
func (l *Layout) LogPath() string      { return filepath.Join(l.Root, "sf6guard.log") }

// Config is the persisted installation configuration.
type Config struct {
	// GameDir is the SF6 install directory.
	GameDir string `json:"game_dir"`
	// BlockNetworkWhenModded installs a temporary outbound firewall block for
	// the duration of a modded session, so a modded client cannot reach
	// Capcom's servers at all.
	BlockNetworkWhenModded bool `json:"block_network_when_modded"`
	// VerifyLoadedModules additionally inspects the running game's loaded
	// modules. Off by default: enforcement is filesystem-side, which achieves
	// the same result without any process introspection near an anti-cheat.
	VerifyLoadedModules bool `json:"verify_loaded_modules"`
	// WatchDuringSession keeps watching the game directory while the game runs
	// and terminates it if a proxy DLL appears mid-session.
	WatchDuringSession bool `json:"watch_during_session"`
}

// DefaultConfig returns the configuration SF6Guard installs with.
func DefaultConfig() Config {
	return Config{
		BlockNetworkWhenModded: true,
		VerifyLoadedModules:    false,
		WatchDuringSession:     true,
	}
}

// LoadConfig reads the configuration.
func (l *Layout) LoadConfig() (*Config, error) {
	data, err := os.ReadFile(l.ConfigPath())
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("SF6Guard is not installed yet — run `sf6guard install` first")
	}
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

// SaveConfig writes the configuration.
func (l *Layout) SaveConfig(cfg *Config) error {
	if err := os.MkdirAll(l.Root, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(l.ConfigPath(), data, 0o644)
}
