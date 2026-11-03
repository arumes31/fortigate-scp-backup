package renderpdf

import (
	"context"
	"errors"
	"math"
)

// wrapText measures each distinct rune once and carries the remaining width
// across word breaks. Measuring every growing prefix makes zero-width text
// quadratic and prevents cancellation inside the PDF library's wrapper.
//
// The embedded fonts use gopdf's default disabled kerning and zero character
// spacing, so their advances are additive. Keep that configuration when using
// this wrapper. The cache is local because the active font and size can change
// between calls. A space at a word break is omitted; hard newlines and long
// unbroken words retain the existing layout behavior.
func wrapText(ctx context.Context, text string, width float64, measure func(string) (float64, error)) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if width <= 0 || math.IsNaN(width) || math.IsInf(width, 0) {
		return nil, errors.New("reports: invalid text layout width")
	}
	widths := make(map[rune]float64)
	var lines []string
	start, space := 0, -1
	lineWidth, widthAfterSpace := 0.0, 0.0
	for offset, r := range text {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if r == '\n' {
			lines = append(lines, text[start:offset])
			start, space = offset+1, -1
			lineWidth = 0
			continue
		}
		advance, ok := widths[r]
		if !ok {
			var err error
			advance, err = measure(string(r))
			if err != nil {
				return nil, err
			}
			if advance < 0 || math.IsNaN(advance) || math.IsInf(advance, 0) {
				return nil, errors.New("reports: invalid glyph advance")
			}
			widths[r] = advance
		}
		// A word break may leave a suffix that still cannot fit the next
		// glyph; at most one subsequent hard break is needed. Never rewind
		// or rescan the suffix, including arbitrarily many combining marks.
		// A glyph wider than the column advances on its own line instead of
		// being retried forever or dropped from the report.
		for lineWidth+advance > width && offset > start {
			if space > start {
				lines = append(lines, text[start:space])
				start = space + 1 // The break indicator is an ASCII space.
				lineWidth -= widthAfterSpace
			} else {
				lines = append(lines, text[start:offset])
				start = offset
				lineWidth = 0
			}
			space = -1
		}
		lineWidth += advance
		if r == ' ' {
			space, widthAfterSpace = offset, lineWidth
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
