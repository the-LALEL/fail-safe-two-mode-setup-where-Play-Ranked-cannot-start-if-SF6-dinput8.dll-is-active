//go:build !windows

// Package gamedir locates the Steam installation and the SF6 game directory.
package gamedir

import (
	"fmt"
	"os"
	"path/filepath"
)

// SteamRoot returns the Steam installation directory.
//
// Outside Windows this exists so the package builds and so the install flow can
// be exercised in tests via SF6GUARD_STEAM_ROOT.
func SteamRoot() (string, error) {
	if override := os.Getenv("SF6GUARD_STEAM_ROOT"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err == nil {
		for _, candidate := range []string{
			filepath.Join(home, ".steam", "steam"),
			filepath.Join(home, ".local", "share", "Steam"),
		} {
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("could not locate the Steam installation directory")
}
