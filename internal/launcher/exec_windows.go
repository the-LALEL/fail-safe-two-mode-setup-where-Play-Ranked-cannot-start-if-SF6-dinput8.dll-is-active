//go:build windows

package launcher

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
)

// buildCommand hands the raw command line to CreateProcess verbatim.
//
// Go normally builds a command line by quoting each element of Args. That round
// trip is lossy for the paths Steam produces, so CmdLine is set explicitly and
// Args is left for Go's own bookkeeping only. Path still has to be resolved so
// exec.Cmd knows which image to start.
func buildCommand(rawCmdLine string) (*exec.Cmd, error) {
	argv, err := windows.DecomposeCommandLine(rawCmdLine)
	if err != nil {
		return nil, fmt.Errorf("parsing the game command line: %w", err)
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty game command line")
	}

	exePath, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, fmt.Errorf("locating %s: %w", argv[0], err)
	}

	cmd := exec.Command(exePath)
	cmd.SysProcAttr = &windows.SysProcAttr{CmdLine: rawCmdLine}
	return cmd, nil
}
