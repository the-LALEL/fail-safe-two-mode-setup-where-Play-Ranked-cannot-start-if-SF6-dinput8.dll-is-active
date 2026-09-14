// Package gate is the enforcement point.
//
// Every Steam launch of SF6 runs through here, because SF6Guard installs itself
// into the game's Steam launch options as `sf6guard.exe gate -- %command%`.
// That placement is what makes the guarantee hold across every launch path
// there is: the library button, a desktop shortcut, Big Picture, a friend's
// invite, a steam:// URL. There is no side door, because Steam itself is the
// door.
//
// The decision is deliberately lopsided. Launching modded requires a valid
// single-use token; everything else is clean. A user who forgets gets a clean
// session automatically, which is the entire point — forgetting is no longer a
// way to end up in Ranked with REFramework injected.
package gate

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/the-lalel/sf6guard/internal/manifest"
	"github.com/the-lalel/sf6guard/internal/paths"
	"github.com/the-lalel/sf6guard/internal/state"
	"github.com/the-lalel/sf6guard/internal/token"
	"github.com/the-lalel/sf6guard/internal/vault"
)

// Mode is the outcome of the gate's decision.
type Mode string

const (
	// ModeRanked is the clean, online-safe path.
	ModeRanked Mode = "ranked"
	// ModeModded is the authorised, network-blocked, offline path.
	ModeModded Mode = "modded"
)

// Firewall installs and removes the modded session's outbound block.
// Implemented natively on Windows; faked in tests.
type Firewall interface {
	Block(exePath string) error
	Unblock() error
	IsBlocked() (bool, error)
}

// Launcher starts the game and waits for it to exit.
type Launcher interface {
	// Start runs the given raw command line and returns a handle to the
	// running process.
	Start(rawCmdLine string) (Process, error)
}

// Process is a running game.
type Process interface {
	PID() int
	Wait() error
	Terminate() error
}

// Watcher observes the game directory during a session.
type Watcher interface {
	// Watch blocks until the session ends or an artifact appears, in which case
	// it returns the offending path.
	Watch(gameDir string, done <-chan struct{}) (violation string, err error)
}

// UI reports refusals to the user in a way they cannot miss.
type UI interface {
	// Refuse shows a blocking message explaining why the game will not start.
	Refuse(title, message string)
	// Notify shows a non-blocking informational message.
	Notify(title, message string)
}

// Deps are the gate's collaborators.
type Deps struct {
	Layout   *paths.Layout
	Config   *paths.Config
	Store    *state.Store
	Vault    *vault.Vault
	Firewall Firewall
	Launcher Launcher
	Watcher  Watcher
	UI       UI
	Log      func(format string, args ...any)
	Now      func() time.Time
}

func (d *Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Deps) logf(format string, args ...any) {
	if d.Log != nil {
		d.Log(format, args...)
	}
}

// Result describes what the gate did.
type Result struct {
	Mode Mode
	// Launched reports whether the game was actually started.
	Launched bool
	// Findings are the reasons a refusal happened, if any.
	Findings []manifest.Finding
}

// ErrRefused means the gate declined to launch the game.
var ErrRefused = errors.New("launch refused")

// Run executes the gate for a raw command line supplied by Steam.
func Run(d *Deps, rawCmdLine string) (*Result, error) {
	gameCmd, err := SplitCommand(rawCmdLine)
	if err != nil {
		return nil, err
	}
	return RunCommand(d, gameCmd)
}

// RunCommand executes the gate for an already-extracted game command line.
func RunCommand(d *Deps, gameCmd string) (*Result, error) {
	cfg := d.Config
	gameDir := cfg.GameDir

	if err := manifest.ValidateGameDir(gameDir); err != nil {
		return nil, refuse(d, "SF6Guard cannot verify the game", err.Error())
	}

	// A modded session that ended badly leaves mod files deployed with nothing
	// scheduled to remove them. Recovering here, before the mode decision,
	// means a crash cannot carry a modded directory into the next launch.
	st, err := d.Store.Load()
	if err != nil {
		return nil, refuse(d, "SF6Guard cannot read its own state", err.Error())
	}
	if st.NeedsRecovery() {
		d.logf("previous modded session did not clean up; recovering")
		if err := recoverSession(d, st); err != nil {
			return nil, refuse(d, "SF6Guard could not clean up after a previous modded session",
				fmt.Sprintf("%v\n\nThe game has not been started. Run `sf6guard clean` and check the vault.", err))
		}
	}

	mode := decideMode(d)
	d.logf("gate decision: %s", mode)

	switch mode {
	case ModeModded:
		return runModded(d, gameCmd)
	default:
		return runRanked(d, gameCmd)
	}
}

// decideMode consumes any intent token and reports which path to take.
//
// Every failure to validate a token resolves to ranked. That is the safe
// direction: the worst outcome of wrongly choosing ranked is that the user has
// to click "Play Modded" again, whereas wrongly choosing modded is the exact
// accident this program exists to prevent.
func decideMode(d *Deps) Mode {
	key, err := token.LoadOrCreateKey(d.Layout.KeyPath())
	if err != nil {
		d.logf("token key unavailable (%v); defaulting to ranked", err)
		return ModeRanked
	}
	err = token.Consume(d.Layout.TokenPath(), key, manifest.SteamAppID, d.now())
	switch {
	case err == nil:
		return ModeModded
	case errors.Is(err, token.ErrNoToken):
		return ModeRanked
	default:
		d.logf("intent token rejected (%v); defaulting to ranked", err)
		return ModeRanked
	}
}

// runRanked sweeps the game directory clean, proves it is clean, and only then
// starts the game.
func runRanked(d *Deps, gameCmd string) (*Result, error) {
	gameDir := d.Config.GameDir

	// Any leftover block from a modded session would silently break online play,
	// which is its own kind of failure. Clear it before a clean launch.
	if d.Firewall != nil {
		if blocked, err := d.Firewall.IsBlocked(); err == nil && blocked {
			d.logf("removing stale modded firewall block")
			if err := d.Firewall.Unblock(); err != nil {
				return nil, refuse(d, "SF6Guard could not remove the modded network block",
					fmt.Sprintf("%v\n\nStarting now would give you a broken online session. Run `sf6guard clean` as administrator.", err))
			}
		}
	}

	swept, err := d.Vault.Sweep(gameDir)
	if err != nil {
		return nil, refuse(d, "Ranked launch blocked — could not disable the mod",
			fmt.Sprintf("SF6Guard tried to move the mod out of the game folder and failed:\n\n%v\n\nThe game has NOT been started.", err))
	}
	for _, item := range swept {
		d.logf("swept %s into the vault", item.RelPath)
	}

	m, err := manifest.Load(d.Layout.ManifestPath())
	if err != nil {
		return nil, refuse(d, "Ranked launch blocked — no clean baseline",
			fmt.Sprintf("%v\n\nThe game has NOT been started.", err))
	}

	findings, err := manifest.Verify(gameDir, m)
	if err != nil {
		return nil, refuse(d, "Ranked launch blocked — verification failed",
			fmt.Sprintf("%v\n\nThe game has NOT been started.", err))
	}
	if len(findings) > 0 {
		return &Result{Mode: ModeRanked, Findings: findings},
			refuse(d, "Ranked launch blocked — the game folder is not clean", findingsMessage(findings))
	}

	if err := d.Store.MarkClean(); err != nil {
		d.logf("warning: could not record clean state: %v", err)
	}
	d.logf("game directory verified clean; launching")

	proc, err := d.Launcher.Start(gameCmd)
	if err != nil {
		return nil, fmt.Errorf("starting the game: %w", err)
	}

	superviseSession(d, gameDir, proc)
	return &Result{Mode: ModeRanked, Launched: true}, nil
}

// runModded deploys the vaulted mod behind a network block and launches.
func runModded(d *Deps, gameCmd string) (*Result, error) {
	gameDir := d.Config.GameDir
	exePath := FirstToken(gameCmd)

	firewallActive := false
	if d.Config.BlockNetworkWhenModded {
		if d.Firewall == nil {
			return nil, refuse(d, "Modded launch blocked — no firewall control",
				"SF6Guard is configured to block network access during modded sessions but cannot control the firewall on this system.\n\nThe game has NOT been started.")
		}
		if err := d.Firewall.Block(exePath); err != nil {
			return nil, refuse(d, "Modded launch blocked — could not block network access",
				fmt.Sprintf("%v\n\nA modded session is only allowed offline, so SF6Guard will not start the game without the block in place.", err))
		}
		// Trusting the call to have worked is not good enough when the whole
		// safety property rests on it. Confirm the rule is really there.
		blocked, err := d.Firewall.IsBlocked()
		if err != nil || !blocked {
			_ = d.Firewall.Unblock()
			return nil, refuse(d, "Modded launch blocked — network block could not be confirmed",
				"SF6Guard asked Windows Firewall to block SF6's outbound traffic but could not confirm the rule is active.\n\nThe game has NOT been started.")
		}
		firewallActive = true
		d.logf("outbound network block active for %s", exePath)
	}

	// Mark the directory modded *before* deploying anything, so an interruption
	// at any point from here on is recoverable on the next launch.
	if err := d.Store.BeginModdedSession(0, firewallActive); err != nil {
		if firewallActive {
			_ = d.Firewall.Unblock()
		}
		return nil, refuse(d, "Modded launch blocked — could not record session state",
			fmt.Sprintf("%v\n\nSF6Guard will not deploy the mod without a way to guarantee it gets removed again.", err))
	}

	deployed, err := d.Vault.Deploy(gameDir)
	if err != nil {
		d.logf("deploy failed: %v", err)
		if cleanupErr := cleanupModdedSession(d); cleanupErr != nil {
			d.logf("cleanup after failed deploy also failed: %v", cleanupErr)
		}
		return nil, refuse(d, "Modded launch blocked — could not install the mod",
			fmt.Sprintf("%v\n\nThe game folder has been returned to its clean state.", err))
	}
	for _, item := range deployed {
		d.logf("deployed %s", item.RelPath)
	}

	proc, err := d.Launcher.Start(gameCmd)
	if err != nil {
		_ = cleanupModdedSession(d)
		return nil, fmt.Errorf("starting the game: %w", err)
	}

	// Wait for the session to finish, then put everything back. This is the
	// normal path; the state marker covers the abnormal ones.
	if err := proc.Wait(); err != nil {
		d.logf("game exited with error: %v", err)
	}
	if err := cleanupModdedSession(d); err != nil {
		d.UI.Refuse("SF6Guard could not fully clean up",
			fmt.Sprintf("The modded session ended but cleanup failed:\n\n%v\n\nRun `sf6guard clean` before playing online.", err))
		return &Result{Mode: ModeModded, Launched: true}, err
	}
	d.logf("modded session ended; game directory returned to clean")
	return &Result{Mode: ModeModded, Launched: true}, nil
}

// cleanupModdedSession returns the directory to clean and lifts the block.
func cleanupModdedSession(d *Deps) error {
	var errs []error

	if _, err := d.Vault.Sweep(d.Config.GameDir); err != nil {
		errs = append(errs, fmt.Errorf("sweeping the mod back to the vault: %w", err))
	}
	if d.Firewall != nil {
		if err := d.Firewall.Unblock(); err != nil {
			errs = append(errs, fmt.Errorf("removing the network block: %w", err))
		}
	}
	if len(errs) == 0 {
		if err := d.Store.MarkClean(); err != nil {
			errs = append(errs, fmt.Errorf("recording clean state: %w", err))
		}
	}
	return errors.Join(errs...)
}

// recoverSession handles a modded session that never cleaned up after itself.
func recoverSession(d *Deps, st *state.State) error {
	if !st.SessionStartedAt.IsZero() {
		d.logf("recovering session started at %s", st.SessionStartedAt.Format(time.RFC3339))
	}
	return cleanupModdedSession(d)
}

// superviseSession watches the game directory for the life of the session.
//
// Injection happens when the process loads, so a proxy DLL appearing after the
// game is already running cannot affect the session in progress. Watching
// anyway catches the case that actually bites people: a mod manager writing
// files into the game folder while the game sits at a menu, which would
// otherwise go unnoticed until the next launch.
func superviseSession(d *Deps, gameDir string, proc Process) {
	if !d.Config.WatchDuringSession || d.Watcher == nil {
		go func() { _ = proc.Wait() }()
		return
	}

	done := make(chan struct{})
	go func() {
		_ = proc.Wait()
		close(done)
	}()

	go func() {
		violation, err := d.Watcher.Watch(gameDir, done)
		if err != nil {
			d.logf("session watcher stopped: %v", err)
			return
		}
		if violation == "" {
			return
		}
		d.logf("mod artifact appeared during a clean session: %s", violation)
		if err := proc.Terminate(); err != nil {
			d.logf("could not terminate the game: %v", err)
		}
		d.UI.Refuse("SF6 was closed — a mod appeared mid-session",
			fmt.Sprintf("%s was written into the game folder while a clean session was running.\n\n"+
				"SF6 has been closed so the session cannot continue in an unknown state.", violation))
	}()
}

func refuse(d *Deps, title, message string) error {
	d.logf("REFUSED: %s — %s", title, strings.ReplaceAll(message, "\n", " "))
	if d.UI != nil {
		d.UI.Refuse(title, message)
	}
	return fmt.Errorf("%w: %s", ErrRefused, title)
}

// findingsMessage renders findings into something a person can act on.
func findingsMessage(findings []manifest.Finding) string {
	var b strings.Builder
	b.WriteString("SF6 has NOT been started.\n\n")
	b.WriteString("The game folder still contains files SF6Guard will not take online:\n\n")
	for _, f := range findings {
		fmt.Fprintf(&b, "  • %s\n      %s\n", f.Path, f.Reason)
	}
	if manifest.HasBlocking(findings) {
		b.WriteString("\nSF6Guard will not move these itself — they are not files it recognises,\n")
		b.WriteString("and guessing could damage your install.\n\n")
		b.WriteString("If SF6 just updated, run:  sf6guard rebaseline\n")
		b.WriteString("Otherwise, verify the game files in Steam.")
	} else {
		b.WriteString("\nRun `sf6guard clean` to move these into the vault.")
	}
	return b.String()
}
