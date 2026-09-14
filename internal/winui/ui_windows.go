//go:build windows

// Package winui shows refusals the user cannot scroll past.
//
// A refusal that only prints to a console nobody sees is not a refusal. When
// Steam launches the gate there is no visible terminal, so a blocked launch
// must announce itself with a real window — otherwise the game simply fails to
// start and the user concludes SF6 is broken.
package winui

import (
	"golang.org/x/sys/windows"
)

const (
	mbOK             = 0x00000000
	mbIconError      = 0x00000010
	mbIconInfo       = 0x00000040
	mbSystemModal    = 0x00001000
	mbSetForeground  = 0x00010000
	mbTopMost        = 0x00040000
)

// Dialog shows native message boxes.
type Dialog struct{}

// New returns a Dialog.
func New() *Dialog { return &Dialog{} }

func show(title, message string, flags uint32) {
	t, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	m, err := windows.UTF16PtrFromString(message)
	if err != nil {
		return
	}
	// A nil owner window is correct here: the gate has no window of its own,
	// and the dialog needs to be visible over whatever Steam has on screen.
	_, _ = windows.MessageBox(0, m, t, flags)
}

// Refuse shows a blocking error dialog and returns once the user dismisses it.
func (d *Dialog) Refuse(title, message string) {
	show(title, message, mbOK|mbIconError|mbSystemModal|mbSetForeground|mbTopMost)
}

// Notify shows an informational dialog.
func (d *Dialog) Notify(title, message string) {
	show(title, message, mbOK|mbIconInfo|mbSetForeground|mbTopMost)
}
