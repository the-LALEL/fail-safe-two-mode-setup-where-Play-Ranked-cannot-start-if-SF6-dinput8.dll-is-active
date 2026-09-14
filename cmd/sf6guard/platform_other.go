//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// openURL hands a URL to the desktop's opener. Present so the CLI builds and
// can be exercised outside Windows.
func openURL(url string) error {
	if _, err := exec.LookPath("xdg-open"); err != nil {
		return fmt.Errorf("cannot open %s on this platform", url)
	}
	return exec.Command("xdg-open", url).Start()
}

// steamIsRunning reports whether Steam has a live process.
func steamIsRunning() (bool, string) {
	out, err := exec.Command("pgrep", "-l", "steam").Output()
	if err != nil {
		return false, ""
	}
	if strings.TrimSpace(string(out)) != "" {
		return true, "steam"
	}
	return false, ""
}
