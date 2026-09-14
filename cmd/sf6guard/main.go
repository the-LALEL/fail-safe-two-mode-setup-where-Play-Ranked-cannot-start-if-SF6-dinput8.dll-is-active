// Command sf6guard enforces a two-mode setup for Street Fighter 6: a clean mode
// that is safe to take online, and a modded mode that cannot reach the network.
//
// The design goal is that forgetting stops mattering. See the package docs in
// internal/gate for why the enforcement point is Steam's launch options.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/the-lalel/sf6guard/internal/gate"
	"github.com/the-lalel/sf6guard/internal/paths"
)

const usage = `sf6guard — fail-safe two-mode launcher for Street Fighter 6

USAGE
  sf6guard <command> [flags]

EVERYDAY COMMANDS
  ranked          Launch SF6 clean. Sweeps the mod out first and verifies.
  modded          Launch SF6 with the mod, with network access blocked.
  status          Show whether the game folder is clean and the gate is armed.

SETUP
  install         Locate SF6 and Steam, capture a clean baseline, install the
                  Steam launch-options gate, register the firewall task.
  adopt <path>    Put a mod file or folder under SF6Guard's control.
  rebaseline      Re-capture the clean baseline after an SF6 update.
  uninstall       Remove the gate and restore the mod to your control.

MAINTENANCE
  clean           Force the game folder back to a verified clean state.
  selftest        Exercise the full sweep/verify/restore cycle on a temp folder.

INTERNAL
  gate -- <cmd>   The enforcement point. Steam invokes this; you do not.
  firewall-sync   Applies firewall changes. Run by the elevated scheduled task.

Run 'sf6guard <command> -h' for command-specific flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "gate":
		err = cmdGate()
	case "ranked":
		err = cmdLaunch(args, false)
	case "modded":
		err = cmdLaunch(args, true)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "adopt":
		err = cmdAdopt(args)
	case "rebaseline":
		err = cmdRebaseline(args)
	case "status":
		err = cmdStatus(args)
	case "clean":
		err = cmdClean(args)
	case "selftest":
		err = cmdSelftest(args)
	case "firewall-sync":
		err = cmdFirewallSync(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "sf6guard: %v\n", err)
		os.Exit(1)
	}
}

// openLog appends to the guard's log file, so a refusal that happened inside a
// Steam launch can be reconstructed afterwards.
func openLog(l *paths.Layout) (io.WriteCloser, func(string, ...any)) {
	if err := os.MkdirAll(l.Root, 0o755); err != nil {
		return nopCloser{}, func(string, ...any) {}
	}
	f, err := os.OpenFile(l.LogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nopCloser{}, func(string, ...any) {}
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(f, "%s  %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}
	return f, logf
}

type nopCloser struct{}

func (nopCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopCloser) Close() error                { return nil }

// cmdGate is what Steam runs. Everything it needs comes from the raw command
// line, because os.Args round-tripping loses Steam's quoting.
func cmdGate() error {
	layout, err := paths.Discover()
	if err != nil {
		return err
	}
	logFile, logf := openLog(layout)
	defer logFile.Close()

	deps, err := buildGateDeps(layout, logf)
	if err != nil {
		// There is no console here, so a setup failure has to be shown.
		newUI().Refuse("SF6Guard is not set up", fmt.Sprintf("%v\n\nSF6 has NOT been started.", err))
		return err
	}

	raw := gate.RawCommandLine()
	logf("gate invoked: %s", raw)

	result, err := gate.Run(deps, raw)
	if err != nil {
		return err
	}
	logf("gate finished: mode=%s launched=%v", result.Mode, result.Launched)
	return nil
}

func fatalUsage(fs *flag.FlagSet, msg string) error {
	fs.Usage()
	return fmt.Errorf("%s", msg)
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  ")
}
