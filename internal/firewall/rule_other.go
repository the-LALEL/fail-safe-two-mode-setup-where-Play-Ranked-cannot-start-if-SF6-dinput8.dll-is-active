//go:build !windows

package firewall

import "fmt"

// The firewall surface only exists on Windows. These stubs let the package —
// and the tests that exercise the reconciler logic — build on other platforms.

func applyRule(d *Desired) error {
	return fmt.Errorf("firewall control is only implemented on Windows")
}

func triggerSyncTask() error {
	return fmt.Errorf("the elevated firewall task is only available on Windows")
}

// RegisterSyncTask is a no-op outside Windows.
func RegisterSyncTask(guardExe, dataDir string) error {
	return fmt.Errorf("scheduled tasks are only available on Windows")
}

// UnregisterSyncTask is a no-op outside Windows.
func UnregisterSyncTask() error { return nil }

// IsElevated reports whether the process has administrator rights.
func IsElevated() bool { return false }
