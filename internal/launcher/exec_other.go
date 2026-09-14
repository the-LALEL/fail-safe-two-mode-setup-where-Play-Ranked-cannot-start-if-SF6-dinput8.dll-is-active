//go:build !windows

package launcher

import (
	"fmt"
	"os/exec"
	"strings"
)

// buildCommand provides a best-effort split for development and tests on
// non-Windows hosts. The real path is the Windows implementation, which passes
// the command line through untouched.
func buildCommand(rawCmdLine string) (*exec.Cmd, error) {
	argv := splitArgs(rawCmdLine)
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty game command line")
	}
	return exec.Command(argv[0], argv[1:]...), nil
}

// splitArgs performs a simple quote-aware split.
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	var inQuotes, started bool

	flush := func() {
		if started {
			args = append(args, cur.String())
			cur.Reset()
			started = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuotes = !inQuotes
			started = true
		case (c == ' ' || c == '\t') && !inQuotes:
			flush()
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	flush()
	return args
}
