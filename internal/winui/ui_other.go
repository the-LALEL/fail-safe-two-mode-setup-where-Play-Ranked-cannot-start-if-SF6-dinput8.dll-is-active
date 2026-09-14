//go:build !windows

// Package winui shows refusals the user cannot scroll past. Outside Windows it
// falls back to stderr, which is enough for tests and for development.
package winui

import (
	"fmt"
	"os"
	"strings"
)

// Dialog writes messages to stderr.
type Dialog struct{}

// New returns a Dialog.
func New() *Dialog { return &Dialog{} }

func (d *Dialog) Refuse(title, message string) {
	fmt.Fprintf(os.Stderr, "\n%s\n%s\n%s\n\n", strings.Repeat("=", 72), title, message)
}

func (d *Dialog) Notify(title, message string) {
	fmt.Fprintf(os.Stderr, "\n%s\n%s\n\n", title, message)
}
