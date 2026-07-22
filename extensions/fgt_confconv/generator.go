package fgt_confconv

import "strings"

// RenderScript renders a full pipeline run's CLIBlocks into one script, with
// a commented banner ahead of each block, in the order they were produced
// (already the pipeline's canonical run order).
func RenderScript(blocks []CLIBlock) string {
	var sb strings.Builder
	for i, b := range blocks {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("# --- ")
		sb.WriteString(b.Label)
		sb.WriteString(" ---\n")
		for _, l := range b.Lines {
			sb.WriteString(l)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}
