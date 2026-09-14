//go:build windows

package gate

import "golang.org/x/sys/windows"

// RawCommandLine returns the process command line exactly as Windows has it.
//
// This is what lets the gate hand Steam's %command% substitution to
// CreateProcess byte-for-byte, instead of reconstructing it from os.Args and
// hoping the quoting survives.
func RawCommandLine() string {
	return windows.UTF16PtrToString(windows.GetCommandLine())
}
