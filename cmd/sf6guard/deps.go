package main

import (
	"github.com/the-lalel/sf6guard/internal/firewall"
	"github.com/the-lalel/sf6guard/internal/gate"
	"github.com/the-lalel/sf6guard/internal/launcher"
	"github.com/the-lalel/sf6guard/internal/paths"
	"github.com/the-lalel/sf6guard/internal/state"
	"github.com/the-lalel/sf6guard/internal/vault"
	"github.com/the-lalel/sf6guard/internal/watcher"
)

// execLauncher adapts the concrete launcher to the gate's interface.
type execLauncher struct{ inner *launcher.Exec }

func (e execLauncher) Start(raw string) (gate.Process, error) {
	p, err := e.inner.Start(raw)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func newUI() gate.UI { return newDialog() }

// buildGateDeps assembles everything the gate needs from an installed
// configuration.
func buildGateDeps(layout *paths.Layout, logf func(string, ...any)) (*gate.Deps, error) {
	cfg, err := layout.LoadConfig()
	if err != nil {
		return nil, err
	}
	v, err := vault.New(layout.VaultDir())
	if err != nil {
		return nil, err
	}

	deps := &gate.Deps{
		Layout:   layout,
		Config:   cfg,
		Store:    state.NewStore(layout.StatePath()),
		Vault:    v,
		Launcher: execLauncher{inner: launcher.New()},
		UI:       newUI(),
		Log:      logf,
	}

	if cfg.BlockNetworkWhenModded {
		deps.Firewall = firewall.NewController(layout.Root)
	}
	if cfg.WatchDuringSession {
		deps.Watcher = watcher.New()
	}
	return deps, nil
}
