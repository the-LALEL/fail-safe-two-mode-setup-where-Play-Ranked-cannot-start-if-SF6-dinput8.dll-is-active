package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/the-lalel/sf6guard/internal/firewall"
	"github.com/the-lalel/sf6guard/internal/gamedir"
	"github.com/the-lalel/sf6guard/internal/manifest"
	"github.com/the-lalel/sf6guard/internal/paths"
	"github.com/the-lalel/sf6guard/internal/state"
	"github.com/the-lalel/sf6guard/internal/steamcfg"
	"github.com/the-lalel/sf6guard/internal/vault"
)

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	gameDirFlag := fs.String("game-dir", "", "SF6 install directory (auto-detected if omitted)")
	steamRootFlag := fs.String("steam-root", "", "Steam install directory (auto-detected if omitted)")
	noSteamHook := fs.Bool("no-steam-hook", false, "skip writing Steam launch options (not recommended — the gate is what makes this fail-safe)")
	noFirewall := fs.Bool("no-firewall", false, "do not block network access during modded sessions")
	assumeYes := fs.Bool("y", false, "do not prompt for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}

	layout, err := paths.Discover()
	if err != nil {
		return err
	}

	steamRoot := *steamRootFlag
	if steamRoot == "" {
		steamRoot, err = gamedir.SteamRoot()
		if err != nil {
			return fmt.Errorf("%w\n\nPass --steam-root to point at it manually", err)
		}
	}
	fmt.Printf("Steam:      %s\n", steamRoot)

	gameDir := *gameDirFlag
	if gameDir == "" {
		gameDir, err = steamcfg.FindAppInstallDir(steamRoot, manifest.SteamAppID)
		if err != nil {
			return fmt.Errorf("%w\n\nPass --game-dir to point at it manually", err)
		}
	}
	gameDir = mustAbs(gameDir)
	if err := manifest.ValidateGameDir(gameDir); err != nil {
		return err
	}
	fmt.Printf("SF6:        %s\n", gameDir)

	guardExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating this executable: %w", err)
	}
	guardExe = mustAbs(guardExe)
	fmt.Printf("SF6Guard:   %s\n", guardExe)
	fmt.Printf("Data:       %s\n\n", layout.Root)

	// The baseline must be captured from a clean directory, otherwise the mod
	// gets recorded as if it belonged there — which would quietly defeat the
	// entire mechanism. So sweep first, then capture.
	v, err := vault.New(layout.VaultDir())
	if err != nil {
		return err
	}
	swept, err := v.Sweep(gameDir)
	if err != nil {
		return fmt.Errorf("moving existing mod files into the vault: %w", err)
	}
	if len(swept) > 0 {
		fmt.Println("Moved these out of the game folder and into the vault:")
		for _, item := range swept {
			fmt.Printf("  • %s\n", item.RelPath)
		}
		fmt.Println()
	}

	leftovers, err := listUnknownRootFiles(gameDir)
	if err != nil {
		return err
	}
	if len(leftovers) > 0 && !*assumeYes {
		fmt.Println("The game folder root currently contains:")
		for _, name := range leftovers {
			fmt.Printf("  • %s\n", name)
		}
		fmt.Println("\nThese will be recorded as part of the clean baseline.")
		fmt.Println("If any of them is a mod, cancel now and remove it first.")
		if !confirm("Record this as your clean baseline?") {
			return fmt.Errorf("cancelled")
		}
		fmt.Println()
	}

	m, err := manifest.Capture(gameDir)
	if err != nil {
		return fmt.Errorf("capturing the clean baseline: %w", err)
	}
	if err := m.Save(layout.ManifestPath()); err != nil {
		return err
	}
	fmt.Printf("Clean baseline captured: %d files in the game root.\n", len(m.Entries))

	cfg := paths.DefaultConfig()
	cfg.GameDir = gameDir
	cfg.BlockNetworkWhenModded = !*noFirewall
	if err := layout.SaveConfig(&cfg); err != nil {
		return err
	}
	if err := state.NewStore(layout.StatePath()).MarkClean(); err != nil {
		return err
	}

	if cfg.BlockNetworkWhenModded {
		if err := installFirewallTask(guardExe, layout.Root); err != nil {
			fmt.Printf("\n!! Could not register the elevated firewall task:\n%s\n", indent(err.Error()))
			fmt.Println("   Modded sessions will refuse to start until this works.")
			fmt.Println("   Re-run `sf6guard install` from an Administrator terminal.")
		} else {
			fmt.Printf("Firewall task registered: %s\n", firewall.TaskName)
		}
	}

	if !*noSteamHook {
		if err := installSteamHook(steamRoot, guardExe, *assumeYes); err != nil {
			return err
		}
	} else {
		fmt.Printf("\n!! Skipped the Steam launch-options gate.\n")
		fmt.Printf("   Without it, launching from the Steam library bypasses SF6Guard entirely.\n")
		fmt.Printf("   Set this by hand in SF6 > Properties > Launch Options:\n\n%s\n\n",
			indent(steamcfg.LaunchOptionsFor(guardExe)))
	}

	fmt.Println("\nInstalled.")
	if empty, _ := v.IsEmpty(); empty {
		fmt.Println("\nThe vault is empty — SF6Guard has no mod to deploy yet.")
		fmt.Printf("Add one with:  sf6guard adopt \"C:\\path\\to\\dinput8.dll\"\n")
	}
	fmt.Println("\nNext: run `sf6guard status` to confirm the gate is armed.")
	return nil
}

// listUnknownRootFiles returns the executable-ish files in the game root, which
// are what a user should eyeball before a baseline is recorded.
func listUnknownRootFiles(gameDir string) ([]string, error) {
	entries, err := os.ReadDir(gameDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".dll" || ext == ".exe" || ext == ".asi" {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func installFirewallTask(guardExe, dataDir string) error {
	if !firewall.IsElevated() {
		return fmt.Errorf("administrator rights are required to register the scheduled task")
	}
	return firewall.RegisterSyncTask(guardExe, dataDir)
}

// installSteamHook writes the launch options that route every Steam launch
// through the gate.
func installSteamHook(steamRoot, guardExe string, assumeYes bool) error {
	if running, name := steamIsRunning(); running {
		return fmt.Errorf("Steam appears to be running (%s).\n\n"+
			"Steam rewrites its config from memory when it exits, so it would silently\n"+
			"undo this change. Close Steam completely, then re-run `sf6guard install`", name)
	}

	configs, err := steamcfg.UserLocalConfigPaths(steamRoot)
	if err != nil {
		return err
	}
	options := steamcfg.LaunchOptionsFor(guardExe)

	fmt.Printf("\nSetting SF6 launch options for %d Steam profile(s):\n%s\n",
		len(configs), indent(options))

	for _, cfgPath := range configs {
		current, err := steamcfg.ReadLaunchOptions(cfgPath, manifest.SteamAppID)
		if err != nil {
			fmt.Printf("  !! %s: %v\n", cfgPath, err)
			continue
		}
		if steamcfg.HooksGuard(current, guardExe) {
			fmt.Printf("  ✓ %s (already set)\n", shorten(cfgPath))
			continue
		}
		if current != "" && !assumeYes {
			fmt.Printf("\n  %s already has launch options:\n%s\n", shorten(cfgPath), indent(current))
			if !confirm("  Replace them?") {
				fmt.Println("  skipped")
				continue
			}
		}
		backup, err := steamcfg.SetLaunchOptions(cfgPath, manifest.SteamAppID, options)
		if err != nil {
			return fmt.Errorf("writing launch options to %s: %w\n\nA backup is at %s", cfgPath, err, backup)
		}
		fmt.Printf("  ✓ %s (backup: %s)\n", shorten(cfgPath), filepath.Base(backup))
	}
	return nil
}

func shorten(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	if len(parts) <= 4 {
		return p
	}
	return ".../" + strings.Join(parts[len(parts)-4:], "/")
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(sc.Text()))
	return answer == "y" || answer == "yes"
}

func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	steamRootFlag := fs.String("steam-root", "", "Steam install directory (auto-detected if omitted)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	layout, err := paths.Discover()
	if err != nil {
		return err
	}
	cfg, err := layout.LoadConfig()
	if err != nil {
		return err
	}

	// Leaving the game folder modded on the way out would be a rude surprise.
	fmt.Println("Returning the game folder to a clean state...")
	if err := forceClean(layout, cfg); err != nil {
		return fmt.Errorf("could not clean the game folder: %w", err)
	}

	steamRoot := *steamRootFlag
	if steamRoot == "" {
		steamRoot, _ = gamedir.SteamRoot()
	}
	if steamRoot != "" {
		if running, name := steamIsRunning(); running {
			fmt.Printf("!! Steam is running (%s) — close it and re-run to clear the launch options.\n", name)
		} else if configs, err := steamcfg.UserLocalConfigPaths(steamRoot); err == nil {
			for _, cfgPath := range configs {
				if _, err := steamcfg.SetLaunchOptions(cfgPath, manifest.SteamAppID, ""); err != nil {
					fmt.Printf("!! %s: %v\n", shorten(cfgPath), err)
					continue
				}
				fmt.Printf("✓ cleared launch options in %s\n", shorten(cfgPath))
			}
		}
	}

	if err := firewall.UnregisterSyncTask(); err != nil {
		fmt.Printf("!! could not remove the scheduled task (it may need administrator rights)\n")
	} else {
		fmt.Printf("✓ removed the scheduled task\n")
	}

	fmt.Printf("\nSF6Guard is uninstalled. Your mod is still in the vault:\n%s\n", indent(layout.VaultDir()))
	fmt.Println("\nDelete that folder yourself if you no longer want it.")
	return nil
}
