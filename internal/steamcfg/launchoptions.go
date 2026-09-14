package steamcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LaunchOptionsFor returns the launch-options string that routes a Steam launch
// through the gate.
//
// The quoting matters: the guard's path can contain spaces, and %command% must
// be left for Steam to substitute.
func LaunchOptionsFor(guardExe string) string {
	return fmt.Sprintf(`"%s" gate -- %%command%%`, guardExe)
}

// HooksGuard reports whether a launch-options string routes through the given
// guard executable.
func HooksGuard(launchOptions, guardExe string) bool {
	if launchOptions == "" {
		return false
	}
	lower := strings.ToLower(launchOptions)
	return strings.Contains(lower, strings.ToLower(filepath.Base(guardExe))) &&
		strings.Contains(lower, "gate") &&
		strings.Contains(lower, "%command%")
}

// userLocalConfigKeys is the path within localconfig.vdf to a user's per-app
// settings.
var userLocalConfigKeys = []string{"UserLocalConfigStore", "Software", "Valve", "Steam", "apps"}

// ReadLaunchOptions returns the current launch options for an app.
func ReadLaunchOptions(localConfigPath, appID string) (string, error) {
	root, err := LoadFile(localConfigPath)
	if err != nil {
		return "", err
	}
	apps, ok := root.ChildPath(userLocalConfigKeys...)
	if !ok {
		return "", nil
	}
	app, ok := apps.Child(appID)
	if !ok {
		return "", nil
	}
	opts, _ := app.Get("LaunchOptions")
	return opts, nil
}

// SetLaunchOptions writes launch options for an app, backing up the original
// file first.
//
// Steam rewrites localconfig.vdf from memory when it exits, so it must not be
// running when this is called — otherwise the edit is silently reverted. The
// caller is responsible for checking; this function's job is to make the edit
// safely and reversibly.
//
// It returns the path of the backup it took.
func SetLaunchOptions(localConfigPath, appID, options string) (backupPath string, err error) {
	original, err := os.ReadFile(localConfigPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", localConfigPath, err)
	}

	root, err := Parse(string(original))
	if err != nil {
		return "", err
	}

	backupPath = fmt.Sprintf("%s.sf6guard-backup-%s", localConfigPath, time.Now().UTC().Format("20060102-150405"))
	if err := os.WriteFile(backupPath, original, 0o644); err != nil {
		return "", fmt.Errorf("writing backup: %w", err)
	}

	apps := root.EnsureChildPath(userLocalConfigKeys...)
	app, ok := apps.Child(appID)
	if !ok {
		app = NewNode()
		apps.touch(appID)
		apps.Children[appID] = app
	}
	app.Set("LaunchOptions", options)

	rendered := root.Render()

	// Re-parse what is about to be written and confirm it round-trips to the
	// intended value. Handing Steam a config file that fails to parse would be
	// a genuinely bad outcome, so it is worth proving before the write.
	check, err := Parse(rendered)
	if err != nil {
		return backupPath, fmt.Errorf("refusing to write: the rewritten config does not parse back (%w)", err)
	}
	checkApps, ok := check.ChildPath(userLocalConfigKeys...)
	if !ok {
		return backupPath, fmt.Errorf("refusing to write: the rewritten config lost the apps section")
	}
	checkApp, ok := checkApps.Child(appID)
	if !ok {
		return backupPath, fmt.Errorf("refusing to write: the rewritten config lost app %s", appID)
	}
	if got, _ := checkApp.Get("LaunchOptions"); got != options {
		return backupPath, fmt.Errorf("refusing to write: launch options did not round-trip (got %q)", got)
	}

	tmp := localConfigPath + ".sf6guard-tmp"
	if err := os.WriteFile(tmp, []byte(rendered), 0o644); err != nil {
		return backupPath, fmt.Errorf("writing new config: %w", err)
	}
	if err := os.Rename(tmp, localConfigPath); err != nil {
		return backupPath, fmt.Errorf("replacing config: %w", err)
	}
	return backupPath, nil
}

// LibraryFolders returns every Steam library path recorded in
// libraryfolders.vdf, including the primary one.
func LibraryFolders(steamRoot string) ([]string, error) {
	candidates := []string{
		filepath.Join(steamRoot, "steamapps", "libraryfolders.vdf"),
		filepath.Join(steamRoot, "config", "libraryfolders.vdf"),
	}

	folders := []string{filepath.Join(steamRoot, "steamapps")}
	for _, path := range candidates {
		root, err := LoadFile(path)
		if err != nil {
			continue
		}
		lf, ok := root.Child("libraryfolders")
		if !ok {
			continue
		}
		for _, key := range lf.Keys {
			entry, ok := lf.Children[key]
			if !ok {
				continue
			}
			if p, ok := entry.Get("path"); ok && p != "" {
				folders = append(folders, filepath.Join(p, "steamapps"))
			}
		}
	}
	return dedupe(folders), nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := strings.ToLower(filepath.Clean(s))
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

// FindAppInstallDir locates an installed app's directory by reading its
// appmanifest across all Steam libraries.
func FindAppInstallDir(steamRoot, appID string) (string, error) {
	folders, err := LibraryFolders(steamRoot)
	if err != nil {
		return "", err
	}
	for _, steamapps := range folders {
		mf := filepath.Join(steamapps, fmt.Sprintf("appmanifest_%s.acf", appID))
		root, err := LoadFile(mf)
		if err != nil {
			continue
		}
		state, ok := root.Child("AppState")
		if !ok {
			continue
		}
		installDir, ok := state.Get("installdir")
		if !ok || installDir == "" {
			continue
		}
		full := filepath.Join(steamapps, "common", installDir)
		if info, err := os.Stat(full); err == nil && info.IsDir() {
			return full, nil
		}
	}
	return "", fmt.Errorf("could not find an installed app %s in any Steam library under %s", appID, steamRoot)
}

// UserLocalConfigPaths returns the localconfig.vdf of every Steam user profile
// on the machine.
func UserLocalConfigPaths(steamRoot string) ([]string, error) {
	userdata := filepath.Join(steamRoot, "userdata")
	entries, err := os.ReadDir(userdata)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", userdata, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "0" || e.Name() == "ac" {
			continue
		}
		p := filepath.Join(userdata, e.Name(), "config", "localconfig.vdf")
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no Steam user profiles found under %s", userdata)
	}
	return out, nil
}
