// Package steamcfg reads Steam's configuration files and installs SF6Guard's
// launch-options hook.
//
// Writing into localconfig.vdf is what gives SF6Guard its reach. A launcher
// that only guards its own shortcut guards nothing, because the user will
// eventually press Play in the Steam library out of habit — and that is exactly
// the moment the mod is still installed. Putting the gate in Steam's own launch
// options means Steam runs it no matter which door the launch came through.
package steamcfg

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Node is a parsed VDF object. Steam's config files are a simple nested
// key/value format: quoted keys followed by either a quoted value or a braced
// block.
type Node struct {
	// Keys preserves declaration order so a rewritten file stays diffable
	// against the original.
	Keys     []string
	Values   map[string]string
	Children map[string]*Node
}

// NewNode returns an empty node.
func NewNode() *Node {
	return &Node{Values: map[string]string{}, Children: map[string]*Node{}}
}

func (n *Node) touch(key string) {
	for _, k := range n.Keys {
		if strings.EqualFold(k, key) {
			return
		}
	}
	n.Keys = append(n.Keys, key)
}

// Set assigns a scalar value.
func (n *Node) Set(key, value string) {
	n.touch(key)
	n.Values[key] = value
}

// Get returns a scalar value, case-insensitively.
func (n *Node) Get(key string) (string, bool) {
	for k, v := range n.Values {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// Child returns a child node, case-insensitively.
func (n *Node) Child(key string) (*Node, bool) {
	for k, v := range n.Children {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// ChildPath walks a chain of child keys.
func (n *Node) ChildPath(keys ...string) (*Node, bool) {
	cur := n
	for _, k := range keys {
		next, ok := cur.Child(k)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// EnsureChildPath walks a chain of child keys, creating nodes as needed.
func (n *Node) EnsureChildPath(keys ...string) *Node {
	cur := n
	for _, k := range keys {
		next, ok := cur.Child(k)
		if !ok {
			next = NewNode()
			cur.touch(k)
			cur.Children[k] = next
		}
		cur = next
	}
	return cur
}

// Parse reads VDF text.
func Parse(text string) (*Node, error) {
	root := NewNode()
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)

	stack := []*Node{root}
	// pendingKey holds a key whose opening brace has not been seen yet.
	var pendingKey []string

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		cur := stack[len(stack)-1]

		if line == "{" {
			if len(pendingKey) == 0 {
				return nil, fmt.Errorf("unexpected `{` with no preceding key")
			}
			key := pendingKey[len(pendingKey)-1]
			pendingKey = pendingKey[:len(pendingKey)-1]

			child := NewNode()
			cur.touch(key)
			cur.Children[key] = child
			stack = append(stack, child)
			continue
		}
		if line == "}" {
			if len(stack) == 1 {
				return nil, fmt.Errorf("unbalanced `}`")
			}
			stack = stack[:len(stack)-1]
			continue
		}

		key, value, hasValue, err := parseLine(line)
		if err != nil {
			return nil, err
		}
		if hasValue {
			cur.Set(key, value)
		} else {
			pendingKey = append(pendingKey, key)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(stack) != 1 {
		return nil, fmt.Errorf("unbalanced braces: %d blocks left open", len(stack)-1)
	}
	return root, nil
}

// parseLine handles `"key"` and `"key"  "value"`.
func parseLine(line string) (key, value string, hasValue bool, err error) {
	key, rest, err := readQuoted(line)
	if err != nil {
		return "", "", false, err
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return key, "", false, nil
	}
	value, _, err = readQuoted(rest)
	if err != nil {
		return "", "", false, err
	}
	return key, value, true, nil
}

func readQuoted(s string) (value, rest string, err error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, `"`) {
		return "", "", fmt.Errorf("expected a quoted token, got %q", s)
	}
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i+1])
			}
			i += 2
			continue
		}
		if c == '"' {
			return b.String(), s[i+1:], nil
		}
		b.WriteByte(c)
		i++
	}
	return "", "", fmt.Errorf("unterminated quoted token in %q", s)
}

func escape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return r.Replace(s)
}

// Render writes the node tree back to VDF text using Steam's tab-indented style.
func (n *Node) Render() string {
	var b strings.Builder
	n.render(&b, 0)
	return b.String()
}

func (n *Node) render(b *strings.Builder, depth int) {
	indent := strings.Repeat("\t", depth)
	for _, key := range n.Keys {
		if v, ok := n.Values[key]; ok {
			fmt.Fprintf(b, "%s\"%s\"\t\t\"%s\"\n", indent, escape(key), escape(v))
			continue
		}
		if child, ok := n.Children[key]; ok {
			fmt.Fprintf(b, "%s\"%s\"\n%s{\n", indent, escape(key), indent)
			child.render(b, depth+1)
			fmt.Fprintf(b, "%s}\n", indent)
		}
	}
}

// SortedKeys returns the node's keys in a stable order, for display.
func (n *Node) SortedKeys() []string {
	out := append([]string(nil), n.Keys...)
	sort.Strings(out)
	return out
}

// LoadFile parses a VDF file from disk.
func LoadFile(path string) (*Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	node, err := Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filepath.Base(path), err)
	}
	return node, nil
}
