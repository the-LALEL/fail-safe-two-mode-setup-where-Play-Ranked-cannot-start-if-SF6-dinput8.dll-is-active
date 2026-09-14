// Package vault moves mod artifacts between the game directory and a holding
// area outside it.
//
// The steady state SF6Guard maintains is: the game directory is clean, and the
// mod lives in the vault. A modded session is a temporary, explicitly
// authorised deviation that is undone when the session ends — or, if the
// session died badly, on the next launch of any kind.
//
// Every operation here is written to fail closed. A sweep that cannot complete
// leaves an error for the gate to refuse on, never a silent partial state.
package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/the-lalel/sf6guard/internal/manifest"
)

// Vault is a directory holding mod artifacts while the game runs clean.
type Vault struct {
	Dir string
}

// New returns a Vault rooted at dir, creating it if needed.
func New(dir string) (*Vault, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating vault: %w", err)
	}
	return &Vault{Dir: dir}, nil
}

// Item is one artifact held in the vault.
type Item struct {
	// RelPath is the artifact's path relative to the game directory.
	RelPath string `json:"rel_path"`
	// IsDir distinguishes reframework/ from dinput8.dll.
	IsDir bool `json:"is_dir"`
	// SHA256 pins a file artifact's contents so tampering between sessions is
	// visible. Empty for directories.
	SHA256 string `json:"sha256,omitempty"`
	// Size is the file size in bytes. Zero for directories.
	Size int64 `json:"size,omitempty"`
}

// Contents is the vault's index of what it is holding.
type Contents struct {
	Items []Item `json:"items"`
}

const indexName = "vault-index.json"

func (v *Vault) indexPath() string { return filepath.Join(v.Dir, indexName) }

// Index reads the vault index, returning an empty Contents if none exists.
func (v *Vault) Index() (*Contents, error) {
	data, err := os.ReadFile(v.indexPath())
	if os.IsNotExist(err) {
		return &Contents{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading vault index: %w", err)
	}
	var c Contents
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing vault index: %w", err)
	}
	return &c, nil
}

func (v *Vault) saveIndex(c *Contents) error {
	sort.Slice(c.Items, func(i, j int) bool { return c.Items[i].RelPath < c.Items[j].RelPath })
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := v.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, v.indexPath())
}

// IsEmpty reports whether the vault is holding nothing.
func (v *Vault) IsEmpty() (bool, error) {
	c, err := v.Index()
	if err != nil {
		return false, err
	}
	return len(c.Items) == 0, nil
}

// sweepTargets lists the mod artifacts currently present in the game directory.
//
// It returns only artifacts SF6Guard is confident it owns: the mod directories,
// and root files with DLL-hijack proxy names. Anything else unexpected in the
// game directory is deliberately *not* swept — moving a file SF6Guard does not
// understand could damage a legitimate game install, so the gate refuses on
// those instead and asks the user to decide.
func sweepTargets(gameDir string) ([]Item, error) {
	var items []Item

	for _, d := range manifest.ModDirs() {
		p := filepath.Join(gameDir, d)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			items = append(items, Item{RelPath: d, IsDir: true})
		}
	}

	entries, err := os.ReadDir(gameDir)
	if err != nil {
		return nil, fmt.Errorf("reading game directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !manifest.IsProxyDLL(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", e.Name(), err)
		}
		sum, err := manifest.HashFile(filepath.Join(gameDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("hashing %s: %w", e.Name(), err)
		}
		items = append(items, Item{RelPath: e.Name(), SHA256: sum, Size: info.Size()})
	}

	sort.Slice(items, func(i, j int) bool { return items[i].RelPath < items[j].RelPath })
	return items, nil
}

// Sweep moves every mod artifact out of the game directory and into the vault.
//
// It returns the items moved. An error means the game directory may still be
// modded and the caller must not launch.
func (v *Vault) Sweep(gameDir string) ([]Item, error) {
	if err := manifest.ValidateGameDir(gameDir); err != nil {
		return nil, err
	}
	targets, err := sweepTargets(gameDir)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}

	index, err := v.Index()
	if err != nil {
		return nil, err
	}

	var moved []Item
	for _, item := range targets {
		src := filepath.Join(gameDir, item.RelPath)
		dst := filepath.Join(v.Dir, item.RelPath)

		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return moved, fmt.Errorf("preparing vault slot for %s: %w", item.RelPath, err)
		}
		// A previous copy in the vault is stale by definition — the live one in
		// the game directory is what the user last used.
		if err := os.RemoveAll(dst); err != nil {
			return moved, fmt.Errorf("clearing stale vault entry %s: %w", item.RelPath, err)
		}
		if err := movePath(src, dst); err != nil {
			return moved, fmt.Errorf("moving %s out of the game directory: %w", item.RelPath, err)
		}
		moved = append(moved, item)
		index.Items = upsert(index.Items, item)
	}

	if err := v.saveIndex(index); err != nil {
		return moved, fmt.Errorf("saving vault index: %w", err)
	}
	return moved, nil
}

// Deploy moves the vault's contents into the game directory, verifying each
// file against the hash recorded when it was swept.
//
// A hash mismatch aborts the deploy. Something changed the mod files while they
// were parked, and silently installing them would defeat the point of pinning
// them in the first place.
func (v *Vault) Deploy(gameDir string) ([]Item, error) {
	if err := manifest.ValidateGameDir(gameDir); err != nil {
		return nil, err
	}
	index, err := v.Index()
	if err != nil {
		return nil, err
	}
	if len(index.Items) == 0 {
		return nil, errors.New("vault is empty — there is nothing to deploy (use `sf6guard adopt` to put the mod under SF6Guard's control)")
	}

	var deployed []Item
	for _, item := range index.Items {
		src := filepath.Join(v.Dir, item.RelPath)
		dst := filepath.Join(gameDir, item.RelPath)

		if _, err := os.Stat(src); err != nil {
			return deployed, fmt.Errorf("vault is missing %s: %w", item.RelPath, err)
		}
		if !item.IsDir && item.SHA256 != "" {
			sum, err := manifest.HashFile(src)
			if err != nil {
				return deployed, fmt.Errorf("hashing vaulted %s: %w", item.RelPath, err)
			}
			if sum != item.SHA256 {
				return deployed, fmt.Errorf(
					"vaulted %s does not match its pinned hash (expected %s, got %s) — refusing to deploy a file that changed while it was parked",
					item.RelPath, short(item.SHA256), short(sum))
			}
		}
		if err := os.RemoveAll(dst); err != nil {
			return deployed, fmt.Errorf("clearing %s in the game directory: %w", item.RelPath, err)
		}
		if err := movePath(src, dst); err != nil {
			return deployed, fmt.Errorf("deploying %s: %w", item.RelPath, err)
		}
		deployed = append(deployed, item)
	}

	// The vault index still lists the items; they are now on loan to the game
	// directory and the sweep on session end brings them back.
	return deployed, nil
}

// Adopt takes a mod artifact that is currently outside SF6Guard's control and
// files it in the vault, so that later deploys have something to install.
func (v *Vault) Adopt(srcPath, relPath string) (Item, error) {
	info, err := os.Stat(srcPath)
	if err != nil {
		return Item{}, fmt.Errorf("reading %s: %w", srcPath, err)
	}

	item := Item{RelPath: relPath, IsDir: info.IsDir()}
	if !info.IsDir() {
		sum, err := manifest.HashFile(srcPath)
		if err != nil {
			return Item{}, err
		}
		item.SHA256 = sum
		item.Size = info.Size()
	}

	dst := filepath.Join(v.Dir, relPath)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return Item{}, err
	}
	if err := os.RemoveAll(dst); err != nil {
		return Item{}, err
	}
	if err := copyPath(srcPath, dst); err != nil {
		return Item{}, fmt.Errorf("copying %s into the vault: %w", relPath, err)
	}

	index, err := v.Index()
	if err != nil {
		return Item{}, err
	}
	index.Items = upsert(index.Items, item)
	if err := v.saveIndex(index); err != nil {
		return Item{}, err
	}
	return item, nil
}

func upsert(items []Item, item Item) []Item {
	for i, existing := range items {
		if strings.EqualFold(existing.RelPath, item.RelPath) {
			items[i] = item
			return items
		}
	}
	return append(items, item)
}

func short(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12] + "…"
}

// movePath moves src to dst, falling back to copy-then-delete when the two are
// on different volumes.
//
// The fallback verifies the copy before removing the original, so a failure
// mid-move never destroys the only copy of the user's mod.
func movePath(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyPath(src, dst); err != nil {
		return err
	}
	if err := verifyCopy(src, dst); err != nil {
		// Leave both copies in place. Losing the mod is worse than a failed
		// sweep, and the gate refuses to launch on this error anyway.
		return fmt.Errorf("copy verification failed, original left intact: %w", err)
	}
	return os.RemoveAll(src)
}

func copyPath(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst, info.Mode())
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := copyPath(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// verifyCopy confirms dst faithfully reproduces src.
func verifyCopy(src, dst string) error {
	si, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if si.IsDir() {
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := verifyCopy(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	a, err := hashFile(src)
	if err != nil {
		return err
	}
	b, err := hashFile(dst)
	if err != nil {
		return err
	}
	if a != b {
		return fmt.Errorf("%s: content mismatch after copy", filepath.Base(src))
	}
	return nil
}

func hashFile(path string) (string, error) {
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
