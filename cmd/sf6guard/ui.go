package main

import (
	"github.com/the-lalel/sf6guard/internal/gate"
	"github.com/the-lalel/sf6guard/internal/winui"
)

func newDialog() gate.UI { return winui.New() }
