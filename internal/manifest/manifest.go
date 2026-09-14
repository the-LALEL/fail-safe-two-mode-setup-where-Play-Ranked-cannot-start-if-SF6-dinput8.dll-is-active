// Package manifest defines what a "clean" Street Fighter 6 installation looks
// like, and detects the artifacts that make it modded.
//
// The threat being modelled is not an adversary. It is the user forgetting that
// a mod is installed. So detection favours being loud and fail-closed over being
// clever: anything the baseline does not vouch for is treated as suspect, and
// the caller is expected to refuse rather than guess.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// HashSizeLimit caps which files get hashed when a baseline is captured.
//
// SF6 ships tens of gigabytes of .pak data; hashing it on every launch would
// make the gate unusably slow. Injection vectors are all small (DLLs and
// executables), so files above this limit are tracked by size alone. A repacked
// .pak mod changes either the name or the size, which is enough to catch it.
const HashSizeLimit = 64 << 20 // 64 MiB

// GameExe is the SF6 executable, used to locate and sanity-check the game
// directory. SF6Guard never renames or replaces it — doing so would break
// Steam's integrity checks and is exactly the sort of tampering anti-cheat
// exists to detect.
const GameExe = "StreetFighter6.exe"

// SteamAppID is Street Fighter 6 on Steam.
const SteamAppID = "1364780"

// proxyDLLNames are DLLs that Windows resolves from the application directory
// before falling back to System32. Dropping any of them next to the game
// executable causes the game to load it at process start, which is how
// REFramework (and every other proxy loader) gets injected.
//
// dinput8.dll is the one REFramework actually uses on SF6, but the whole family
// is listed: a gate that only knows one name is a gate that a different mod
// walks straight through.
var proxyDLLNames = []string{
	"d3d8.dll",
	"d3d9.dll",
	"d3d10.dll",
	"d3d11.dll",
	"d3d12.dll",
	"dbghelp.dll",
	"dinput.dll",
	"dinput8.dll",
	"dsound.dll",
	"dxgi.dll",
	"opengl32.dll",
	"version.dll",
	"wininet.dll",
	"winmm.dll",
	"xinput1_1.dll",
	"xinput1_2.dll",
	"xinput1_3.dll",
	"xinput1_4.dll",
	"xinput9_1_0.dll",
	"bink2w64.dll",
	"winhttp.dll",
	"msvcp140.dll.bak", // a common "I disabled it by renaming" leftover
}

// IsProxyDLL reports whether name is a known DLL-hijack proxy name.
func IsProxyDLL(name string) bool {
	lower := strings.ToLower(filepath.Base(name))
	for _, p := range proxyDLLNames {
		if lower == p {
			return true
		}
	}
	return false
}

// ProxyDLLNames returns a copy of the proxy name list, for display.
func ProxyDLLNames() []string {
	out := make([]string, len(proxyDLLNames))
	copy(out, proxyDLLNames)
	return out
}

// modDirs are directories that only exist because a mod put them there.
// Sweeping these is what makes a modded install revert to clean.
var modDirs = []string{
	"reframework", // REFramework config, logs, autorun scripts, plugins
	"natives",     // loose-file asset mods loaded by LooseFileLoader
	"pak_mods",    // some RE Engine mod managers stage repacked paks here
}

// ModDirs returns the directory names treated as mod-owned.
func ModDirs() []string {
	out := make([]string, len(modDirs))
	copy(out, modDirs)
	return out
}

// Entry is one file recorded in the game directory root.
type Entry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"` // empty for files above HashSizeLimit
}

// Manifest is a baseline of a known-clean game directory root.
//
// Only the root is recorded, non-recursively. That is where proxy DLLs must
// land to be loaded, so it is the only place a baseline needs to cover, and it
// keeps capture fast enough to run on demand.
type Manifest struct {
	Version    int       `json:"version"`
	GameDir    string    `json:"game_dir"`
	CapturedAt time.Time `json:"captured_at"`
	Entries    []Entry   `json:"entries"`
}

const manifestVersion = 1

// Capture records the current state of the game directory root as the clean
// baseline. The caller is responsible for having established that the directory
// really is clean first — Capture records what it is told, it does not judge.
func Capture(gameDir string) (*Manifest, error) {
	if err := ValidateGameDir(gameDir); err != nil {
		return nil, err
	}
	items, err := os.ReadDir(gameDir)
	if err != nil {
		return nil, fmt.Errorf("reading game directory: %w", err)
	}
	m := &Manifest{
		Version:    manifestVersion,
		GameDir:    gameDir,
		CapturedAt: time.Now().UTC(),
	}
	for _, it := range items {
		if it.IsDir() {
			continue
		}
		info, err := it.Info()
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", it.Name(), err)
		}
		e := Entry{Name: it.Name(), Size: info.Size()}
		if info.Size() <= HashSizeLimit {
			sum, err := HashFile(filepath.Join(gameDir, it.Name()))
			if err != nil {
				return nil, fmt.Errorf("hashing %s: %w", it.Name(), err)
			}
			e.SHA256 = sum
		}
		m.Entries = append(m.Entries, e)
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Name < m.Entries[j].Name })
	return m, nil
}

// ValidateGameDir checks that dir actually looks like an SF6 install, so a
// misconfigured path cannot cause SF6Guard to sweep files out of, say, the
// user's Documents folder.
func ValidateGameDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("game directory is not configured")
	}
	exe := filepath.Join(dir, GameExe)
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("%s not found in %s — this does not look like an SF6 install", GameExe, dir)
	}
	return nil
}

// HashFile returns the lowercase hex SHA-256 of the file at path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Save writes the manifest to path as indented JSON.
func (m *Manifest) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Load reads a manifest from path.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", path, err)
	}
	if m.Version != manifestVersion {
		return nil, fmt.Errorf("manifest %s has version %d, expected %d — re-run `sf6guard rebaseline`", path, m.Version, manifestVersion)
	}
	return &m, nil
}

func (m *Manifest) lookup(name string) (Entry, bool) {
	for _, e := range m.Entries {
		if strings.EqualFold(e.Name, name) {
			return e, true
		}
	}
	return Entry{}, false
}

// Severity distinguishes findings that the gate can fix by sweeping from those
// that require the user to make a decision.
type Severity int

const (
	// Sweepable means the finding is a known mod artifact that the vault can
	// move out of the way, after which the directory is clean.
	Sweepable Severity = iota
	// Blocking means SF6Guard will not touch the file and will not launch.
	// Something is present that the baseline cannot vouch for, and guessing
	// would risk deleting legitimate game data.
	Blocking
)

func (s Severity) String() string {
	if s == Sweepable {
		return "sweepable"
	}
	return "blocking"
}

// Finding is one reason the game directory is not verified clean.
type Finding struct {
	Path     string // path relative to the game directory
	Severity Severity
	Reason   string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s — %s", f.Severity, f.Path, f.Reason)
}

// Verify compares the live game directory against the baseline and returns
// every reason it is not clean. An empty result means verified clean.
//
// The rules, in order of how much they matter:
//
//  1. Any proxy DLL in the root is a finding, always, even if a stale baseline
//     happens to contain it. This is the rule that actually stops the game
//     starting with REFramework active.
//  2. Any mod-owned directory present is a finding.
//  3. Any file in the root absent from the baseline is a finding — unknown
//     means unvouched-for, and unvouched-for means no launch.
//  4. Any baseline file whose hash or size changed is a finding.
func Verify(gameDir string, m *Manifest) ([]Finding, error) {
	if err := ValidateGameDir(gameDir); err != nil {
		return nil, err
	}
	var findings []Finding

	for _, d := range modDirs {
		p := filepath.Join(gameDir, d)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			findings = append(findings, Finding{
				Path:     d,
				Severity: Sweepable,
				Reason:   "mod directory present",
			})
		}
	}

	items, err := os.ReadDir(gameDir)
	if err != nil {
		return nil, fmt.Errorf("reading game directory: %w", err)
	}

	for _, it := range items {
		if it.IsDir() {
			continue
		}
		name := it.Name()

		if IsProxyDLL(name) {
			findings = append(findings, Finding{
				Path:     name,
				Severity: Sweepable,
				Reason:   "DLL-hijack proxy name — the game loads this at startup",
			})
			continue
		}

		base, known := m.lookup(name)
		if !known {
			findings = append(findings, Finding{
				Path:     name,
				Severity: Blocking,
				Reason:   "not in the clean baseline (run `sf6guard rebaseline` after an SF6 update)",
			})
			continue
		}

		info, err := it.Info()
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", name, err)
		}
		if info.Size() != base.Size {
			findings = append(findings, Finding{
				Path:     name,
				Severity: Blocking,
				Reason: fmt.Sprintf("size changed (baseline %d bytes, now %d) — run `sf6guard rebaseline` after an SF6 update",
					base.Size, info.Size()),
			})
			continue
		}
		if base.SHA256 != "" {
			sum, err := HashFile(filepath.Join(gameDir, name))
			if err != nil {
				return nil, fmt.Errorf("hashing %s: %w", name, err)
			}
			if sum != base.SHA256 {
				findings = append(findings, Finding{
					Path:     name,
					Severity: Blocking,
					Reason:   "contents changed since the clean baseline — run `sf6guard rebaseline` after an SF6 update",
				})
			}
		}
	}

	// Files the baseline expects but that have gone missing are worth flagging;
	// a half-removed mod or a failed update leaves the install in a state
	// nobody should be taking into Ranked.
	for _, e := range m.Entries {
		if _, err := os.Stat(filepath.Join(gameDir, e.Name)); os.IsNotExist(err) {
			findings = append(findings, Finding{
				Path:     e.Name,
				Severity: Blocking,
				Reason:   "expected by the clean baseline but missing — verify game files in Steam",
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].Path < findings[j].Path
	})
	return findings, nil
}

// HasBlocking reports whether any finding requires a human decision, meaning
// the gate cannot resolve the situation by sweeping.
func HasBlocking(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == Blocking {
			return true
		}
	}
	return false
}
