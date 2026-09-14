// Package launcher starts the game.
//
// The command line Steam handed the gate is passed through untouched. SF6Guard
// deliberately does not parse, rewrite or "improve" it: Steam's arguments are
// Steam's business, and a launcher that mangles them is a launcher that breaks
// in ways nobody can diagnose.
package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// Proc is a running game process.
type Proc struct {
	cmd  *exec.Cmd
	once sync.Once
	err  error
	done chan struct{}
}

// PID returns the process ID.
func (p *Proc) PID() int {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Wait blocks until the process exits. It is safe to call from several
// goroutines; every caller sees the same result.
func (p *Proc) Wait() error {
	p.once.Do(func() {
		p.err = p.cmd.Wait()
		close(p.done)
	})
	<-p.done
	return p.err
}

// Terminate stops the process.
func (p *Proc) Terminate() error {
	if p.cmd == nil || p.cmd.Process == nil {
		return fmt.Errorf("process is not running")
	}
	return p.cmd.Process.Kill()
}

// Exec starts games using the platform's process API.
type Exec struct{}

// New returns an Exec launcher.
func New() *Exec { return &Exec{} }

// Start launches the raw command line.
func (e *Exec) Start(rawCmdLine string) (*Proc, error) {
	cmd, err := buildCommand(rawCmdLine)
	if err != nil {
		return nil, err
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", filepath.Base(cmd.Path), err)
	}
	return &Proc{cmd: cmd, done: make(chan struct{})}, nil
}
