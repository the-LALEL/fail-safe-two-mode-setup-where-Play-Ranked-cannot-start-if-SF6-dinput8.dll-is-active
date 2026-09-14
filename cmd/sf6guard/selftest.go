package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/the-lalel/sf6guard/internal/manifest"
	"github.com/the-lalel/sf6guard/internal/vault"
)

// cmdSelftest proves the sweep/verify/restore cycle works on this machine,
// against a throwaway directory.
//
// The point is that a user should be able to satisfy themselves that the
// mechanism does what it claims without having to gamble their actual SF6
// install — or their account — on finding out.
func cmdSelftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	keep := fs.Bool("keep", false, "keep the temporary directory for inspection")
	if err := fs.Parse(args); err != nil {
		return err
	}

	tmp, err := os.MkdirTemp("", "sf6guard-selftest-")
	if err != nil {
		return err
	}
	if !*keep {
		defer os.RemoveAll(tmp)
	}

	gameDir := filepath.Join(tmp, "game")
	vaultDir := filepath.Join(tmp, "vault")
	if err := os.MkdirAll(gameDir, 0o755); err != nil {
		return err
	}

	fmt.Printf("Working in %s\n\n", tmp)

	// A stand-in game install: the executable the guard looks for, plus a
	// legitimate DLL that must survive every step.
	write := func(rel, content string) error {
		p := filepath.Join(gameDir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, []byte(content), 0o644)
	}
	if err := write(manifest.GameExe, "pretend game"); err != nil {
		return err
	}
	if err := write("legit.dll", "a real game dll"); err != nil {
		return err
	}

	step := 0
	check := func(label string, ok bool, detail string) error {
		step++
		status := "ok  "
		if !ok {
			status = "FAIL"
		}
		fmt.Printf("  %s  %d. %s\n", status, step, label)
		if !ok {
			if detail != "" {
				fmt.Printf("        %s\n", detail)
			}
			return fmt.Errorf("selftest failed at step %d: %s", step, label)
		}
		return nil
	}

	base, err := manifest.Capture(gameDir)
	if err != nil {
		return err
	}
	findings, err := manifest.Verify(gameDir, base)
	if err != nil {
		return err
	}
	if err := check("a clean folder verifies clean", len(findings) == 0, fmt.Sprintf("%v", findings)); err != nil {
		return err
	}

	// Plant the mod, exactly as installing REFramework would.
	if err := write("dinput8.dll", "pretend REFramework"); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(gameDir, "reframework", "autorun"), 0o755); err != nil {
		return err
	}

	findings, err = manifest.Verify(gameDir, base)
	if err != nil {
		return err
	}
	if err := check("dinput8.dll is detected", containsPath(findings, "dinput8.dll"), ""); err != nil {
		return err
	}
	if err := check("the reframework folder is detected", containsPath(findings, "reframework"), ""); err != nil {
		return err
	}

	v, err := vault.New(vaultDir)
	if err != nil {
		return err
	}
	swept, err := v.Sweep(gameDir)
	if err != nil {
		return err
	}
	if err := check("both artifacts sweep into the vault", len(swept) == 2, fmt.Sprintf("swept %d", len(swept))); err != nil {
		return err
	}

	_, statErr := os.Stat(filepath.Join(gameDir, "dinput8.dll"))
	if err := check("dinput8.dll is gone from the game folder", os.IsNotExist(statErr), ""); err != nil {
		return err
	}

	findings, err = manifest.Verify(gameDir, base)
	if err != nil {
		return err
	}
	if err := check("the swept folder verifies clean again", len(findings) == 0, fmt.Sprintf("%v", findings)); err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(gameDir, "legit.dll")); err != nil {
		return check("the legitimate DLL survived the sweep", false, err.Error())
	}
	if err := check("the legitimate DLL survived the sweep", true, ""); err != nil {
		return err
	}

	deployed, err := v.Deploy(gameDir)
	if err != nil {
		return err
	}
	if err := check("the vault redeploys for a modded session", len(deployed) == 2, ""); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(gameDir, "dinput8.dll")); err != nil {
		return check("dinput8.dll is back after deploy", false, err.Error())
	}
	if err := check("dinput8.dll is back after deploy", true, ""); err != nil {
		return err
	}

	if _, err := v.Sweep(gameDir); err != nil {
		return err
	}
	findings, err = manifest.Verify(gameDir, base)
	if err != nil {
		return err
	}
	if err := check("end-of-session sweep returns it to clean", len(findings) == 0, fmt.Sprintf("%v", findings)); err != nil {
		return err
	}

	// Tamper with a vaulted file: a deploy must refuse rather than install
	// something that changed while it was parked.
	if err := os.WriteFile(filepath.Join(vaultDir, "dinput8.dll"), []byte("swapped out"), 0o644); err != nil {
		return err
	}
	_, deployErr := v.Deploy(gameDir)
	if err := check("a tampered vault file is refused", deployErr != nil, "deploy unexpectedly succeeded"); err != nil {
		return err
	}

	fmt.Printf("\nAll %d checks passed.\n", step)
	return nil
}

func containsPath(findings []manifest.Finding, path string) bool {
	for _, f := range findings {
		if f.Path == path {
			return true
		}
	}
	return false
}
