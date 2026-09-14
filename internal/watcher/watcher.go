// Package watcher keeps an eye on the game directory while a clean session is
// running.
//
// This layer is not what stops REFramework being injected — injection happens
// when the process loads its DLLs, and by the time the game is running that
// moment has passed. The pre-launch sweep and verification are what provide
// that guarantee.
//
// What this catches is the sloppier, more common sequence: the user alt-tabs
// during a clean session, installs something with a mod manager, and leaves the
// game folder dirty. Without a watcher that goes unnoticed until the next
// launch. With one, the session is stopped and the user is told immediately,
// while the cause is still obvious to them.
//
// It deliberately uses polling rather than process introspection. Nothing here
// opens a handle to the game.
package watcher

import (
	"os"
	"path/filepath"
	"time"

	"github.com/the-lalel/sf6guard/internal/manifest"
)

// Poller scans the game directory at an interval.
type Poller struct {
	// Interval is how often the directory is scanned. A couple of seconds is
	// responsive enough for a human-scale mistake and costs nothing measurable.
	Interval time.Duration
}

// New returns a Poller with a sensible interval.
func New() *Poller { return &Poller{Interval: 2 * time.Second} }

func (p *Poller) interval() time.Duration {
	if p.Interval > 0 {
		return p.Interval
	}
	return 2 * time.Second
}

// Watch blocks until done is closed or a mod artifact appears.
//
// It returns the offending path, or an empty string if the session ended
// cleanly.
func (p *Poller) Watch(gameDir string, done <-chan struct{}) (string, error) {
	ticker := time.NewTicker(p.interval())
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return "", nil
		case <-ticker.C:
			violation, err := scan(gameDir)
			if err != nil {
				// A transient read error (the directory busy, a file locked)
				// is not worth killing a session over. Keep watching.
				continue
			}
			if violation != "" {
				return violation, nil
			}
		}
	}
}

// scan looks for artifacts that should not exist during a clean session.
func scan(gameDir string) (string, error) {
	for _, d := range manifest.ModDirs() {
		p := filepath.Join(gameDir, d)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return d, nil
		}
	}

	entries, err := os.ReadDir(gameDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() && manifest.IsProxyDLL(e.Name()) {
			return e.Name(), nil
		}
	}
	return "", nil
}
