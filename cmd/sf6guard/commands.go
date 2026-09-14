package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/the-lalel/sf6guard/internal/firewall"
	"github.com/the-lalel/sf6guard/internal/gamedir"
	"github.com/the-lalel/sf6guard/internal/manifest"
	"github.com/the-lalel/sf6guard/internal/paths"
	"github.com/the-lalel/sf6guard/internal/state"
	"github.com/the-lalel/sf6guard/internal/steamcfg"
	"github.com/the-lalel/sf6guard/internal/token"
	"github.com/the-lalel/sf6guard/internal/vault"
)

// steamRunGameURL asks Steam to launch the app, which means the launch goes
// through Steam's own machinery — and therefore through the gate installed in
// its launch options. Starting the game executable directly would bypass that,
// which is exactly what this program exists to prevent.
func steamRunGameURL() string {
	return "steam://rungameid/" + manifest.SteamAppID
}

// cmdLaunch implements `ranked` and `modded`.
//
// Neither command starts the game itself. Both ask Steam to start it, so the
// launch arrives at the gate the same way a library-button launch does. The
// only difference between them is whether an intent token is minted first.
func cmdLaunch(args []string, modded bool) error {
	name := "ranked"
	if modded {
		name = "modded"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
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

	if modded {
		v, err := vault.New(layout.VaultDir())
		if err != nil {
			return err
		}
		empty, err := v.IsEmpty()
		if err != nil {
			return err
		}
		if empty {
			return fmt.Errorf("the vault is empty — there is no mod to deploy.\n\n" +
				"Add one first:  sf6guard adopt \"C:\\path\\to\\dinput8.dll\"")
		}

		key, err := token.LoadOrCreateKey(layout.KeyPath())
		if err != nil {
			return err
		}
		if err := token.Mint(layout.TokenPath(), key, manifest.SteamAppID, time.Now()); err != nil {
			return fmt.Errorf("minting the modded intent token: %w", err)
		}
		fmt.Printf("Modded session authorised (valid for %s).\n", token.TTL)
		if cfg.BlockNetworkWhenModded {
			fmt.Println("SF6 will be blocked from reaching the network for this session.")
			fmt.Println("Online modes will not work — that is intentional.")
		}
	} else {
		fmt.Println("Launching clean. The mod will be moved out and the folder verified first.")
	}

	fmt.Printf("Asking Steam to start SF6...\n")
	if err := openURL(steamRunGameURL()); err != nil {
		return fmt.Errorf("asking Steam to launch SF6: %w", err)
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
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

	fmt.Printf("Game folder:  %s\n", cfg.GameDir)
	fmt.Printf("Data folder:  %s\n\n", layout.Root)

	st, err := state.NewStore(layout.StatePath()).Load()
	if err != nil {
		return err
	}
	switch {
	case st.NeedsRecovery():
		fmt.Printf("State:        MODDED — a session did not clean up after itself\n")
		fmt.Printf("              The next launch of any kind will sweep it clean first.\n")
	default:
		fmt.Printf("State:        clean")
		if !st.LastCleanAt.IsZero() {
			fmt.Printf(" (verified %s)", st.LastCleanAt.Local().Format("2006-01-02 15:04"))
		}
		fmt.Println()
	}

	// The live directory is the truth; the state file is only a record of
	// intent. Report what is actually on disk.
	if m, err := manifest.Load(layout.ManifestPath()); err != nil {
		fmt.Printf("Baseline:     MISSING — run `sf6guard install`\n")
	} else {
		findings, err := manifest.Verify(cfg.GameDir, m)
		switch {
		case err != nil:
			fmt.Printf("Game folder:  could not verify: %v\n", err)
		case len(findings) == 0:
			fmt.Printf("Game folder:  VERIFIED CLEAN — safe for Ranked\n")
		default:
			fmt.Printf("Game folder:  NOT CLEAN — Ranked launches will be refused\n")
			for _, f := range findings {
				fmt.Printf("                • %s — %s\n", f.Path, f.Reason)
			}
		}
	}

	v, err := vault.New(layout.VaultDir())
	if err != nil {
		return err
	}
	contents, err := v.Index()
	if err != nil {
		return err
	}
	if len(contents.Items) == 0 {
		fmt.Printf("Vault:        empty — no mod under SF6Guard's control\n")
	} else {
		fmt.Printf("Vault:        %d item(s)\n", len(contents.Items))
		for _, item := range contents.Items {
			if item.IsDir {
				fmt.Printf("                • %s/ (folder)\n", item.RelPath)
				continue
			}
			fmt.Printf("                • %s  sha256:%s\n", item.RelPath, shortHash(item.SHA256))
		}
	}

	fmt.Printf("\nModded network block: %s\n", onOff(cfg.BlockNetworkWhenModded))
	if cfg.BlockNetworkWhenModded {
		ctl := firewall.NewController(layout.Root)
		if blocked, err := ctl.IsBlocked(); err == nil {
			fmt.Printf("  rule currently active: %v\n", blocked)
		}
	}
	fmt.Printf("Session watcher:      %s\n", onOff(cfg.WatchDuringSession))
	fmt.Printf("Module verification:  %s\n", onOff(cfg.VerifyLoadedModules))

	reportSteamHook()
	return nil
}

// reportSteamHook is the most important line of `status`: if the launch options
// are gone, SF6Guard is decorative.
func reportSteamHook() {
	fmt.Println()
	guardExe, err := os.Executable()
	if err != nil {
		return
	}
	steamRoot, err := gamedir.SteamRoot()
	if err != nil {
		fmt.Printf("Steam gate:   could not locate Steam to check\n")
		return
	}
	configs, err := steamcfg.UserLocalConfigPaths(steamRoot)
	if err != nil {
		fmt.Printf("Steam gate:   could not read Steam profiles: %v\n", err)
		return
	}
	var armed, unarmed int
	for _, c := range configs {
		opts, err := steamcfg.ReadLaunchOptions(c, manifest.SteamAppID)
		if err != nil {
			continue
		}
		if steamcfg.HooksGuard(opts, guardExe) {
			armed++
		} else {
			unarmed++
		}
	}
	switch {
	case armed > 0 && unarmed == 0:
		fmt.Printf("Steam gate:   ARMED on %d profile(s) — every Steam launch goes through SF6Guard\n", armed)
	case armed > 0:
		fmt.Printf("Steam gate:   PARTIAL — armed on %d profile(s), NOT armed on %d\n", armed, unarmed)
		fmt.Printf("              Re-run `sf6guard install` with Steam closed.\n")
	default:
		fmt.Printf("Steam gate:   NOT ARMED — launching from Steam bypasses SF6Guard entirely\n")
		fmt.Printf("              Close Steam and re-run `sf6guard install`.\n")
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func shortHash(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}

func cmdClean(args []string) error {
	fs := flag.NewFlagSet("clean", flag.ExitOnError)
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
	if err := forceClean(layout, cfg); err != nil {
		return err
	}
	fmt.Println("Game folder is verified clean and safe for Ranked.")
	return nil
}

// forceClean sweeps, lifts any network block, and verifies.
func forceClean(layout *paths.Layout, cfg *paths.Config) error {
	v, err := vault.New(layout.VaultDir())
	if err != nil {
		return err
	}
	swept, err := v.Sweep(cfg.GameDir)
	if err != nil {
		return err
	}
	for _, item := range swept {
		fmt.Printf("  moved %s into the vault\n", item.RelPath)
	}

	if cfg.BlockNetworkWhenModded {
		ctl := firewall.NewController(layout.Root)
		if blocked, err := ctl.IsBlocked(); err == nil && blocked {
			if err := ctl.Unblock(); err != nil {
				return fmt.Errorf("removing the modded network block: %w", err)
			}
			fmt.Println("  removed the modded network block")
		}
	}

	m, err := manifest.Load(layout.ManifestPath())
	if err != nil {
		return err
	}
	findings, err := manifest.Verify(cfg.GameDir, m)
	if err != nil {
		return err
	}
	if len(findings) > 0 {
		var b strings.Builder
		b.WriteString("the game folder is still not clean:\n")
		for _, f := range findings {
			fmt.Fprintf(&b, "  • %s — %s\n", f.Path, f.Reason)
		}
		return fmt.Errorf("%s", b.String())
	}
	return state.NewStore(layout.StatePath()).MarkClean()
}

func cmdAdopt(args []string) error {
	fs := flag.NewFlagSet("adopt", flag.ExitOnError)
	asName := fs.String("as", "", "name to install it under in the game folder (default: the source's own name)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fatalUsage(fs, "adopt takes exactly one path")
	}

	src := mustAbs(fs.Arg(0))
	relPath := *asName
	if relPath == "" {
		relPath = filepath.Base(src)
	}

	layout, err := paths.Discover()
	if err != nil {
		return err
	}
	if _, err := layout.LoadConfig(); err != nil {
		return err
	}
	v, err := vault.New(layout.VaultDir())
	if err != nil {
		return err
	}

	item, err := v.Adopt(src, relPath)
	if err != nil {
		return err
	}

	if item.IsDir {
		fmt.Printf("Adopted %s as %s/ (folder)\n", src, item.RelPath)
	} else {
		fmt.Printf("Adopted %s\n", src)
		fmt.Printf("  installs as: %s\n", item.RelPath)
		fmt.Printf("  size:        %d bytes\n", item.Size)
		fmt.Printf("  sha256:      %s\n", item.SHA256)
		fmt.Printf("\nThis hash is now pinned. If the file changes while it is in the vault,\n")
		fmt.Printf("SF6Guard will refuse to deploy it.\n")
	}

	if !manifest.IsProxyDLL(item.RelPath) && !item.IsDir {
		fmt.Printf("\nNote: %q is not a name the gate recognises as a mod loader.\n", item.RelPath)
		fmt.Printf("It will be deployed for modded sessions, but a stray copy left in the\n")
		fmt.Printf("game folder would NOT be swept automatically. Prefer the real name\n")
		fmt.Printf("(dinput8.dll for REFramework).\n")
	}
	return nil
}

func cmdRebaseline(args []string) error {
	fs := flag.NewFlagSet("rebaseline", flag.ExitOnError)
	assumeYes := fs.Bool("y", false, "do not prompt for confirmation")
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

	v, err := vault.New(layout.VaultDir())
	if err != nil {
		return err
	}
	if _, err := v.Sweep(cfg.GameDir); err != nil {
		return fmt.Errorf("sweeping before rebaseline: %w", err)
	}

	old, err := manifest.Load(layout.ManifestPath())
	if err != nil {
		fmt.Printf("No usable existing baseline (%v) — capturing a fresh one.\n\n", err)
		old = &manifest.Manifest{}
	}

	fresh, err := manifest.Capture(cfg.GameDir)
	if err != nil {
		return err
	}

	added, removed, changed := diffManifests(old, fresh)
	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
		fmt.Println("No changes since the current baseline. Nothing to do.")
		return nil
	}

	fmt.Println("Changes since the current clean baseline:")
	for _, n := range added {
		fmt.Printf("  + %s\n", n)
	}
	for _, n := range removed {
		fmt.Printf("  - %s\n", n)
	}
	for _, n := range changed {
		fmt.Printf("  ~ %s\n", n)
	}

	fmt.Printf("\nThis should match what an SF6 update changed.\n")
	fmt.Printf("If anything above looks like a mod, cancel and investigate first —\n")
	fmt.Printf("accepting it here would teach SF6Guard to treat it as legitimate.\n\n")

	if !*assumeYes && !confirm("Accept these as the new clean baseline?") {
		return fmt.Errorf("cancelled — the existing baseline is unchanged")
	}
	if err := fresh.Save(layout.ManifestPath()); err != nil {
		return err
	}
	fmt.Println("\nNew clean baseline recorded.")
	return nil
}

func diffManifests(old, fresh *manifest.Manifest) (added, removed, changed []string) {
	oldByName := map[string]manifest.Entry{}
	for _, e := range old.Entries {
		oldByName[strings.ToLower(e.Name)] = e
	}
	freshByName := map[string]manifest.Entry{}
	for _, e := range fresh.Entries {
		freshByName[strings.ToLower(e.Name)] = e
	}

	for _, e := range fresh.Entries {
		prev, ok := oldByName[strings.ToLower(e.Name)]
		if !ok {
			added = append(added, e.Name)
			continue
		}
		if prev.Size != e.Size || prev.SHA256 != e.SHA256 {
			changed = append(changed, e.Name)
		}
	}
	for _, e := range old.Entries {
		if _, ok := freshByName[strings.ToLower(e.Name)]; !ok {
			removed = append(removed, e.Name)
		}
	}
	return added, removed, changed
}

func cmdFirewallSync(args []string) error {
	fs := flag.NewFlagSet("firewall-sync", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "SF6Guard data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir := *dataDir
	if dir == "" {
		layout, err := paths.Discover()
		if err != nil {
			return err
		}
		dir = layout.Root
	}
	return firewall.Sync(dir)
}
