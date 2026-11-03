// Package fortiosconfig reads saved FortiOS configuration, without contacting a
// firewall or resolving dynamic objects. Unknown semantics are reported rather
// than interpreted as an empty selector or a successful security check.
package fortiosconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const maxConfigBytes = 32 << 20

type node struct {
	kind, name string
	start, end int
	parent     *node
	children   []*node
	values     map[string][]string
}

type document struct {
	sections []*node
	header   string
	warnings []string
}

func (n *node) get(key string) string { return strings.Join(n.values[key], " ") }
func (n *node) value(key, fallback string) string {
	if value, ok := n.values[key]; ok {
		return strings.Join(value, " ")
	}
	return fallback
}
func (n *node) vdom() string {
	for p := n; p != nil; p = p.parent {
		if p.kind == "edit" && p.parent != nil && p.parent.name == "vdom" {
			return p.name
		}
	}
	if n.parent != nil && n.parent.name == "system interface" && n.get("vdom") != "" {
		return n.get("vdom")
	}
	return "root"
}
func (n *node) evidence() string {
	section := n.name
	if n.kind == "edit" && n.parent != nil {
		section = n.parent.name + " / " + n.name
	}
	return fmt.Sprintf("VDOM %s; %s; lines %d-%d", display(n.vdom()), display(section), n.start, n.end)
}
func (d *document) tables(section string) []*node {
	var result []*node
	for _, n := range d.sections {
		if n.name == section {
			result = append(result, n)
		}
	}
	return result
}
func (d *document) objects(section string) []*node {
	var result []*node
	for _, table := range d.tables(section) {
		for _, n := range table.children {
			if n.kind == "edit" {
				result = append(result, n)
			}
		}
	}
	return result
}

// tokens handles escaped quotes and multiline values. incomplete means another
// physical line belongs to the same value, not to the config nesting grammar.
func tokens(text string) (out []string, incomplete bool) {
	var current strings.Builder
	var quote byte
	active := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(text) {
				i++
				current.WriteByte(text[i])
				continue
			}
			if c == quote {
				quote = 0
			} else {
				current.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			active = true
		case ' ', '\t', '\r', '\n':
			if active {
				out = append(out, current.String())
				current.Reset()
				active = false
			}
		default:
			current.WriteByte(c)
			active = true
		}
	}
	if quote != 0 {
		return nil, true
	}
	if active {
		out = append(out, current.String())
	}
	return out, false
}

// quoteState scans each physical line once. Re-tokenizing the accumulated
// multiline value after every line would make an adversarial script quadratic.
func quoteState(text string, quote byte) byte {
	for i := 0; i < len(text); i++ {
		if quote != 0 {
			if text[i] == '\\' {
				i++
				continue
			}
			if text[i] == quote {
				quote = 0
			}
		} else if text[i] == '\'' || text[i] == '"' {
			quote = text[i]
		}
	}
	return quote
}

func parse(ctx context.Context, plain []byte) (*document, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(plain) == 0 || len(plain) > maxConfigBytes {
		return nil, errors.New("configuration is empty or exceeds the 32 MiB analysis limit")
	}
	if strings.IndexByte(string(plain), 0) >= 0 {
		return nil, errors.New("configuration is not a plaintext FortiOS backup")
	}
	if strings.Count(string(plain), "\n") > 1000000 {
		return nil, errors.New("configuration exceeds the one-million-line parsing limit")
	}
	root := &node{kind: "root", values: map[string][]string{}}
	d := &document{}
	stack := []*node{root}
	lines := strings.Split(string(plain), "\n")
	count := 0
	for i := 0; i < len(lines); i++ {
		if i%64 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		lineNumber := i + 1
		line := strings.TrimSpace(strings.TrimPrefix(lines[i], "\ufeff"))
		if strings.HasPrefix(line, "#config-version=") {
			d.header = line
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 1<<20 {
			return nil, fmt.Errorf("configuration value at line %d exceeds the 1 MiB limit", lineNumber)
		}
		if quote := quoteState(line, 0); quote != 0 {
			var value strings.Builder
			value.WriteString(line)
			for quote != 0 && i+1 < len(lines) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				i++
				if value.Len()+1+len(lines[i]) > 1<<20 {
					return nil, fmt.Errorf("configuration value at line %d exceeds the 1 MiB limit", lineNumber)
				}
				value.WriteByte('\n')
				value.WriteString(lines[i])
				quote = quoteState(lines[i], quote)
			}
			line = value.String()
		}
		fields, incomplete := tokens(line)
		if incomplete {
			return nil, fmt.Errorf("unterminated quoted value at line %d", lineNumber)
		}
		if len(fields) == 0 {
			continue
		}
		current := stack[len(stack)-1]
		switch fields[0] {
		case "config", "edit":
			if len(fields) < 2 || (fields[0] == "edit" && (current.kind != "config" || len(fields) != 2)) {
				return nil, fmt.Errorf("invalid block opener at line %d", lineNumber)
			}
			count++
			if count > 200000 || len(stack) >= 128 {
				return nil, errors.New("configuration nesting or object count exceeds analysis limits")
			}
			n := &node{kind: fields[0], name: strings.Join(fields[1:], " "), start: lineNumber, parent: current, values: map[string][]string{}}
			current.children = append(current.children, n)
			if n.kind == "config" {
				d.sections = append(d.sections, n)
			}
			stack = append(stack, n)
		case "next", "end":
			want := "edit"
			if fields[0] == "end" {
				want = "config"
			}
			if len(fields) != 1 || current.kind != want {
				return nil, fmt.Errorf("unbalanced block terminator at line %d", lineNumber)
			}
			current.end = i + 1
			stack = stack[:len(stack)-1]
		case "set":
			if len(fields) < 3 || current == root {
				return nil, fmt.Errorf("invalid setting at line %d", lineNumber)
			}
			current.values[fields[1]] = fields[2:]
		case "unset":
			if len(fields) != 2 || current == root {
				return nil, fmt.Errorf("invalid unset at line %d", lineNumber)
			}
			delete(current.values, fields[1])
		default:
			d.warnings = append(d.warnings, fmt.Sprintf("Unsupported configuration command at line %d; policy conclusions may be incomplete.", lineNumber))
		}
	}
	if len(stack) != 1 {
		return nil, fmt.Errorf("incomplete configuration: block opened at line %d is not closed", stack[len(stack)-1].start)
	}
	if len(d.sections) == 0 {
		return nil, errors.New("no FortiOS configuration sections found")
	}
	return d, nil
}

// display bounds attacker-controlled labels and removes control characters. It
// does not export arbitrary configuration comments or values from secret keys.
func display(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > 300 {
		return string(runes[:300]) + "…"
	}
	return value
}
