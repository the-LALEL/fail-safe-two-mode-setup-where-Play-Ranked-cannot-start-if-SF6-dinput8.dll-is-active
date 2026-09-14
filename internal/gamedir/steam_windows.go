//go:build windows

// Package gamedir locates the Steam installation and the SF6 game directory.
package gamedir

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// SteamRoot returns the Steam installation directory.
//
// The registry is authoritative; the well-known paths are a fallback for
// installs where the key is missing or points somewhere stale.
func SteamRoot() (string, error) {
	for _, k := range []struct {
		key  registry.Key
		path string
		name string
	}{
		{registry.CURRENT_USER, `Software\Valve\Steam`, "SteamPath"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Valve\Steam`, "InstallPath"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Valve\Steam`, "InstallPath"},
	} {
		key, err := registry.OpenKey(k.key, k.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := key.GetStringValue(k.name)
		key.Close()
		if err != nil || v == "" {
			continue
		}
		v = filepath.FromSlash(v)
		if info, err := os.Stat(v); err == nil && info.IsDir() {
			return v, nil
		}
	}

	for _, candidate := range []string{
		`C:\Program Files (x86)\Steam`,
		`C:\Program Files\Steam`,
	} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not locate the Steam installation directory")
}
