//go:build !windows

package gate

import (
	"os"
	"strings"
)

// RawCommandLine reconstructs a command line from os.Args.
//
// Only Windows has a single authoritative command-line string; elsewhere this
// is a reasonable approximation, used for development and tests.
func RawCommandLine() string {
	parts := make([]string, 0, len(os.Args))
	for _, a := range os.Args {
		if strings.ContainsAny(a, " \t") {
			parts = append(parts, `"`+a+`"`)
			continue
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}
