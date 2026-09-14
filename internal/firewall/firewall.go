// Package firewall installs the outbound block that keeps a modded session
// offline.
//
// This is the control that turns "please don't play Ranked while modded" into
// something the machine enforces. A modded SF6 process with no route to
// Capcom's servers cannot enter Ranked, Casual or Battle Hub at all — not
// because the user remembered, but because the packets do not leave.
//
// # Why this is built as a reconciler
//
// Windows Firewall rules require administrator rights, and a launcher that
// throws a UAC prompt on every modded launch is a launcher people disable. So
// `sf6guard install` registers a scheduled task, once, behind a single
// elevation prompt. That task runs `sf6guard firewall-sync`, which reads a
// desired-state file and makes the firewall match it.
//
// The unprivileged gate therefore never touches the firewall directly. It
// writes what it wants, triggers the task, and waits for the elevated side to
// confirm what it actually did. Confirmation is read back from a result file
// the task writes, because reading firewall rules needs elevation too.
package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RuleName is the Windows Firewall rule SF6Guard manages. It is deliberately
// distinctive so a user can find and inspect it.
const RuleName = "SF6Guard-ModdedBlock"

// TaskName is the scheduled task that applies firewall changes with elevation.
const TaskName = "SF6Guard-FirewallSync"

// Desired is what the gate wants the firewall to look like.
type Desired struct {
	Block   bool      `json:"block"`
	ExePath string    `json:"exe_path"`
	SetAt   time.Time `json:"set_at"`
}

// Applied is what the elevated sync actually achieved.
type Applied struct {
	Blocked   bool      `json:"blocked"`
	ExePath   string    `json:"exe_path"`
	AppliedAt time.Time `json:"applied_at"`
	Error     string    `json:"error,omitempty"`
}

// Paths locates the handshake files.
type Paths struct{ Dir string }

func (p Paths) desiredPath() string { return filepath.Join(p.Dir, "firewall-desired.json") }
func (p Paths) appliedPath() string { return filepath.Join(p.Dir, "firewall-applied.json") }

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// ReadDesired returns the currently requested firewall state.
func (p Paths) ReadDesired() (*Desired, error) {
	var d Desired
	if err := readJSON(p.desiredPath(), &d); err != nil {
		if os.IsNotExist(err) {
			return &Desired{Block: false}, nil
		}
		return nil, err
	}
	return &d, nil
}

// WriteDesired records the requested firewall state.
func (p Paths) WriteDesired(d *Desired) error { return writeJSON(p.desiredPath(), d) }

// ReadApplied returns what the elevated sync last achieved.
func (p Paths) ReadApplied() (*Applied, error) {
	var a Applied
	if err := readJSON(p.appliedPath(), &a); err != nil {
		if os.IsNotExist(err) {
			return &Applied{Blocked: false}, nil
		}
		return nil, err
	}
	return &a, nil
}

// WriteApplied records what the elevated sync achieved.
func (p Paths) WriteApplied(a *Applied) error { return writeJSON(p.appliedPath(), a) }

// syncTimeout bounds how long the gate waits for the elevated task to act.
const syncTimeout = 20 * time.Second

// Controller drives the firewall through the elevated sync task.
type Controller struct {
	Paths Paths
	// Trigger runs the elevated sync. Replaced in tests.
	Trigger func() error
	// Now supplies the clock. Replaced in tests.
	Now func() time.Time
	// Poll is how often applied-state is re-read while waiting.
	Poll time.Duration
}

// NewController returns a Controller using the platform's task trigger.
func NewController(dir string) *Controller {
	return &Controller{
		Paths:   Paths{Dir: dir},
		Trigger: triggerSyncTask,
		Now:     time.Now,
		Poll:    250 * time.Millisecond,
	}
}

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Controller) poll() time.Duration {
	if c.Poll > 0 {
		return c.Poll
	}
	return 250 * time.Millisecond
}

// Block installs an outbound block for exePath and waits for confirmation.
func (c *Controller) Block(exePath string) error {
	if exePath == "" {
		return fmt.Errorf("no executable path to block")
	}
	return c.apply(&Desired{Block: true, ExePath: exePath, SetAt: c.now()}, true)
}

// Unblock removes the block and waits for confirmation.
func (c *Controller) Unblock() error {
	return c.apply(&Desired{Block: false, SetAt: c.now()}, false)
}

func (c *Controller) apply(d *Desired, want bool) error {
	if err := c.Paths.WriteDesired(d); err != nil {
		return fmt.Errorf("recording desired firewall state: %w", err)
	}
	if err := c.Trigger(); err != nil {
		return fmt.Errorf("running the elevated firewall task %q: %w\n"+
			"Run `sf6guard install` as administrator to register it", TaskName, err)
	}

	deadline := c.now().Add(syncTimeout)
	var last string
	for c.now().Before(deadline) {
		applied, err := c.Paths.ReadApplied()
		if err == nil && !applied.AppliedAt.Before(d.SetAt) {
			if applied.Error != "" {
				return fmt.Errorf("the elevated firewall task reported: %s", applied.Error)
			}
			if applied.Blocked == want {
				return nil
			}
			last = fmt.Sprintf("task reported blocked=%v, wanted %v", applied.Blocked, want)
		}
		time.Sleep(c.poll())
	}
	if last == "" {
		last = "the elevated task did not report back in time"
	}
	return fmt.Errorf("firewall change not confirmed after %s: %s", syncTimeout, last)
}

// IsBlocked reports whether the block is currently in place, according to the
// last confirmed report from the elevated task.
func (c *Controller) IsBlocked() (bool, error) {
	applied, err := c.Paths.ReadApplied()
	if err != nil {
		return false, err
	}
	return applied.Blocked, nil
}

// Sync is the elevated side. It reads the desired state, makes the firewall
// match, and records what happened.
func Sync(dir string) error {
	p := Paths{Dir: dir}
	desired, err := p.ReadDesired()
	if err != nil {
		return fmt.Errorf("reading desired firewall state: %w", err)
	}

	applyErr := applyRule(desired)

	result := &Applied{
		ExePath:   desired.ExePath,
		AppliedAt: time.Now().UTC(),
	}
	if applyErr != nil {
		result.Error = applyErr.Error()
		// Report the real state rather than the intended one: a failed block
		// must never look like a successful block.
		result.Blocked = false
	} else {
		result.Blocked = desired.Block
	}

	if err := p.WriteApplied(result); err != nil {
		return fmt.Errorf("recording applied firewall state: %w", err)
	}
	return applyErr
}

// NoopController satisfies the interface where firewall control is disabled.
type NoopController struct{}

func (NoopController) Block(string) error    { return fmt.Errorf("firewall control is not available on this platform") }
func (NoopController) Unblock() error        { return nil }
func (NoopController) IsBlocked() (bool, error) { return false, nil }
