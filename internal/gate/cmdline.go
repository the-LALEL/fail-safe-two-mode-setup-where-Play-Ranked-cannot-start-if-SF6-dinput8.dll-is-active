package gate

import (
	"errors"
	"strings"
)

// Sentinel separates SF6Guard's own arguments from the command Steam wants run.
const Sentinel = "--"

// SplitCommand extracts the game command from a raw Windows command line.
//
// Steam substitutes %command% with the executable path and its arguments, so
// the gate is invoked as:
//
//	"C:\SF6Guard\sf6guard.exe" gate -- "C:\...\StreetFighter6.exe" -some -args
//
// Taking this from the raw GetCommandLineW string rather than from os.Args
// matters: parsing into os.Args and re-quoting to rebuild a command line is
// lossy, and the paths involved contain spaces. Splitting the raw string at the
// sentinel hands the tail to CreateProcess byte-for-byte as Steam wrote it.
func SplitCommand(rawCmdLine string) (string, error) {
	tail, found := splitAtSentinel(rawCmdLine)
	if !found {
		return "", errors.New("no `--` sentinel in the command line: the Steam launch options should read `sf6guard.exe gate -- %command%`")
	}
	tail = strings.TrimSpace(tail)
	if tail == "" {
		return "", errors.New("nothing after `--`: Steam did not substitute %command% (check the launch options for AppID 1364780)")
	}
	return tail, nil
}

// splitAtSentinel finds the first bare `--` argument that is not inside quotes
// and returns everything after it.
func splitAtSentinel(s string) (string, bool) {
	var inQuotes bool
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '"' {
			inQuotes = !inQuotes
			i++
			continue
		}
		if inQuotes {
			i++
			continue
		}
		// A sentinel must stand alone as its own argument: preceded by
		// whitespace (or the start of the line) and followed by whitespace.
		if c == '-' && i+1 < len(s) && s[i+1] == '-' {
			atStart := i == 0 || isSpace(s[i-1])
			end := i + 2
			atEnd := end >= len(s) || isSpace(s[end])
			if atStart && atEnd {
				return s[end:], true
			}
		}
		i++
	}
	return "", false
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' }

// FirstToken returns the first argument of a command line, unquoted. It is used
// to identify which executable the gate is about to launch.
func FirstToken(cmdLine string) string {
	s := strings.TrimSpace(cmdLine)
	if s == "" {
		return ""
	}
	if s[0] == '"' {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return s[1 : 1+end]
		}
		return s[1:]
	}
	if end := strings.IndexAny(s, " \t"); end >= 0 {
		return s[:end]
	}
	return s
}
