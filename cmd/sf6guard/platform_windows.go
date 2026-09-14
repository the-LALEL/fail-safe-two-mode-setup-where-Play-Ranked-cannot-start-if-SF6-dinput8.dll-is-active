//go:build windows

package main

import (
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

// openURL hands a steam:// URL to the shell so Steam handles it.
func openURL(url string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	target, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}

// steamIsRunning reports whether Steam has a live process.
//
// This matters because Steam holds localconfig.vdf in memory and rewrites it on
// exit. Editing the file underneath a running Steam means the edit vanishes,
// and the user is left believing the gate is armed when it is not.
func steamIsRunning() (bool, string) {
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq steam.exe", "/NH")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return false, ""
	}
	if strings.Contains(strings.ToLower(string(out)), "steam.exe") {
		return true, "steam.exe"
	}
	return false, ""
}
