package web

import (
	"strings"
)

// This file implements a small structural scanner for FortiGate configuration
// files. It tracks `config … / edit … / next / end` nesting with line numbers
// so audit checks can point at the exact block a finding comes from and show
// the detected line ±3 lines of context.

// cfgBlock is one `config …` or `edit …` block in the configuration.
type cfgBlock struct {
	// Path is the full block path, segments joined by " > ", e.g.
	// "config system admin > edit admin". Paths are stored lowercase except
	// edit names, which keep their original case.
	Path string
	// Name is the edit name for edit blocks ("" for config blocks).
	Name string
	// Start/End are 0-based line indexes of the opening line and the matching
	// `end`/`next` (End == last line index when the file is truncated).
	Start, End int
	// Depth is the nesting depth (0 = top level `config` block).
	Depth int
}

// cfgDoc is a parsed configuration: raw lines plus the block structure.
type cfgDoc struct {
	lines  []string
	blocks []cfgBlock
}

// parseCfg scans the configuration once and records every block with its
// line range.
func parseCfg(cfg string) *cfgDoc {
	lines := strings.Split(cfg, "\n")
	doc := &cfgDoc{lines: lines}

	type openBlock struct {
		path  string
		name  string
		start int
		depth int
	}
	var stack []openBlock

	push := func(seg, name string, i int) {
		path := seg
		if len(stack) > 0 {
			path = stack[len(stack)-1].path + " > " + seg
		}
		stack = append(stack, openBlock{path: path, name: name, start: i, depth: len(stack)})
	}
	pop := func(i int) {
		if len(stack) == 0 {
			return
		}
		ob := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		doc.blocks = append(doc.blocks, cfgBlock{
			Path: ob.path, Name: ob.name, Start: ob.start, End: i, Depth: ob.depth,
		})
	}

	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "config "):
			push(lower, "", i)
		case strings.HasPrefix(lower, "edit "):
			name := strings.Trim(trimmed[5:], `"'`)
			push("edit "+name, name, i)
		case lower == "next":
			pop(i)
		case lower == "end":
			pop(i)
		}
	}
	// Close anything left open (truncated config).
	for len(stack) > 0 {
		pop(len(lines) - 1)
	}
	return doc
}

// pathMatches reports whether a block path equals the wanted section path,
// ignoring any VDOM wrapping: on multi-VDOM FortiGates sections like
// "config system interface" are nested under "config global" or
// "config vdom > edit <name>", producing paths such as
// "config global > config system interface". Matching on the segment-aligned
// suffix keeps the checks working in both modes.
func pathMatches(blockPath, path string) bool {
	return blockPath == path || strings.HasSuffix(blockPath, " > "+path)
}

// block returns the first block whose path matches the section (VDOM
// wrapping ignored; edit names compare case-sensitively as stored).
func (d *cfgDoc) block(path string) (cfgBlock, bool) {
	for _, b := range d.blocks {
		if pathMatches(b.Path, path) {
			return b, true
		}
	}
	return cfgBlock{}, false
}

// blocksUnder returns every direct edit block under the given config path,
// e.g. blocksUnder("config system admin") yields one block per admin. VDOM
// wrapping is ignored, and with multiple VDOMs the edits of every VDOM's
// section are collected.
func (d *cfgDoc) blocksUnder(path string) []cfgBlock {
	key := path + " > edit "
	var out []cfgBlock
	for _, b := range d.blocks {
		idx := strings.Index(b.Path, key)
		if idx < 0 {
			continue
		}
		// The section must start the path or sit on a segment boundary
		// (VDOM prefix), and the edit must be the last segment.
		if idx > 0 && !strings.HasSuffix(b.Path[:idx], " > ") {
			continue
		}
		if strings.Contains(b.Path[idx+len(key):], " > ") {
			continue
		}
		out = append(out, b)
	}
	return out
}

// findDirect finds the first line with the given prefix (after trimming,
// case-insensitive) directly inside the block, skipping nested child blocks.
// Returns the 0-based line index.
func (d *cfgDoc) findDirect(b cfgBlock, prefix string) (int, string, bool) {
	depth := 0
	for i := b.Start + 1; i < b.End && i < len(d.lines); i++ {
		trimmed := strings.TrimSpace(d.lines[i])
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "config ") || strings.HasPrefix(lower, "edit "):
			depth++
			continue
		case lower == "end" || lower == "next":
			depth--
			continue
		}
		if depth == 0 && strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return i, trimmed, true
		}
	}
	return 0, "", false
}

// settingDirect returns the value of `set <name> …` directly inside the block
// (nested blocks skipped): the remainder of the line after the setting name,
// with surrounding quotes trimmed.
func (d *cfgDoc) settingDirect(b cfgBlock, name string) (string, int, bool) {
	idx, line, ok := d.findDirect(b, "set "+name+" ")
	if !ok {
		return "", 0, false
	}
	val := strings.TrimSpace(line[len("set "+name+" "):])
	return strings.Trim(val, `"'`), idx, true
}

// settingFields returns the values of `set <name> …` directly inside the
// block as a list, or nil when the setting is absent. Quoted values keep
// embedded spaces ("Internal Net" stays one value) and backslash escapes
// inside quotes are resolved.
func (d *cfgDoc) settingFields(b cfgBlock, name string) []string {
	_, line, ok := d.findDirect(b, "set "+name+" ")
	if !ok {
		return nil
	}
	return splitCfgValues(strings.TrimSpace(line[len("set "+name+" "):]))
}

// splitCfgValues tokenizes a FortiGate `set` value list: whitespace-separated
// tokens, with double/single-quoted strings kept as single values and
// backslash escapes (\" \\) unescaped inside quotes.
func splitCfgValues(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if q := s[i]; q == '"' || q == '\'' {
			i++
			var sb strings.Builder
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				sb.WriteByte(s[i])
				i++
			}
			i++ // closing quote (or past end when unterminated)
			out = append(out, sb.String())
			continue
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		out = append(out, s[start:i])
	}
	return out
}

// context renders the detected line ±3 lines. When the enclosing block's
// closing line lies beyond the window it is appended after an ellipsis so the
// block ending stays visible. Returns the snippet and the 1-based number of
// its first line.
func (d *cfgDoc) context(lineIdx int, b cfgBlock) (string, int) {
	if lineIdx < 0 || lineIdx >= len(d.lines) {
		return "", 0
	}
	start := lineIdx - 3
	if start < 0 {
		start = 0
	}
	stop := lineIdx + 3
	if stop > len(d.lines)-1 {
		stop = len(d.lines) - 1
	}

	var sb strings.Builder
	for i := start; i <= stop; i++ {
		sb.WriteString(strings.TrimRight(d.lines[i], "\r"))
		sb.WriteByte('\n')
	}
	// Append the block ending when it is outside the window.
	if b.End > stop && b.End < len(d.lines) {
		if b.End > stop+1 {
			sb.WriteString("    ...\n")
		}
		sb.WriteString(strings.TrimRight(d.lines[b.End], "\r"))
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n"), start + 1
}

// findingAt builds a finding anchored to the given line inside the block.
// text is the canonical English message, textDE its German rendering.
func (d *cfgDoc) findingAt(checkID, key, severity, text, textDE, remediation string, lineIdx int, b cfgBlock) auditFinding {
	ctx, ctxStart := d.context(lineIdx, b)
	return auditFinding{
		CheckID:      checkID,
		Key:          key,
		Severity:     severity,
		Text:         text,
		TextDE:       textDE,
		Remediation:  remediation,
		Line:         lineIdx + 1,
		Context:      ctx,
		ContextStart: ctxStart,
	}
}
