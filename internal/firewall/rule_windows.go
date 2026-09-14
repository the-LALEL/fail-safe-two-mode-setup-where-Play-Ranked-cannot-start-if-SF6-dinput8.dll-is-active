//go:build windows

package firewall

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

// applyRule makes Windows Firewall match the desired state.
//
// The rule is removed and recreated rather than toggled, because a rule left
// over from an earlier session may point at a different executable path (the
// user moved their Steam library, say) and a stale rule that blocks nothing is
// worse than no rule at all.
func applyRule(d *Desired) error {
	if err := deleteRule(); err != nil {
		return err
	}
	if !d.Block {
		return nil
	}
	return addRule(d.ExePath)
}

func netsh(args ...string) (string, error) {
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func deleteRule() error {
	out, err := netsh("advfirewall", "firewall", "delete", "rule", "name="+RuleName)
	if err != nil {
		// "No rules match the specified criteria" is the expected result when
		// there is nothing to remove, and is not a failure.
		if strings.Contains(strings.ToLower(out), "no rules match") {
			return nil
		}
		return fmt.Errorf("removing firewall rule: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

func addRule(exePath string) error {
	// Block outbound only. Inbound is irrelevant here and blocking it would be
	// noise; the objective is that the modded client cannot reach Capcom's
	// servers, not that it is invisible.
	out, err := netsh("advfirewall", "firewall", "add", "rule",
		"name="+RuleName,
		"dir=out",
		"action=block",
		"enable=yes",
		"profile=any",
		"program="+exePath,
	)
	if err != nil {
		return fmt.Errorf("adding firewall rule for %s: %w: %s", exePath, err, strings.TrimSpace(out))
	}
	return nil
}

// triggerSyncTask runs the elevated scheduled task registered at install time.
func triggerSyncTask() error {
	cmd := exec.Command("schtasks", "/run", "/tn", TaskName)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RegisterSyncTask creates the elevated scheduled task. Requires administrator
// rights, and is called once by `sf6guard install`.
func RegisterSyncTask(guardExe, dataDir string) error {
	_ = UnregisterSyncTask()

	action := fmt.Sprintf(`"%s" firewall-sync --data-dir "%s"`, guardExe, dataDir)
	cmd := exec.Command("schtasks", "/create",
		"/tn", TaskName,
		"/tr", action,
		"/sc", "once",
		"/st", "00:00",
		"/rl", "HIGHEST", // run elevated without prompting at trigger time
		"/f",
	)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("registering scheduled task %q: %w: %s", TaskName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UnregisterSyncTask removes the scheduled task.
func UnregisterSyncTask() error {
	cmd := exec.Command("schtasks", "/delete", "/tn", TaskName, "/f")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// IsElevated reports whether the current process has administrator rights.
func IsElevated() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0) // the current process token
	member, err := token.IsMember(sid)
	return err == nil && member
}
