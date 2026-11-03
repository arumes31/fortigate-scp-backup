package renderpdf

import (
	"math"
	"strings"
)

// Action colors always accompany a literal label. Unknown actions remain
// neutral; configuration-derived strings never become CSS or color values.
type actionTone struct {
	Class                  string
	Foreground, Background [3]uint8
}

func toneForAction(action string) actionTone {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "deny":
		return actionTone{Class: "action-deny", Foreground: [3]uint8{153, 27, 27}, Background: [3]uint8{254, 226, 226}}
	case "accept", "allow":
		return actionTone{Class: "action-allow", Foreground: [3]uint8{22, 101, 52}, Background: [3]uint8{220, 252, 231}}
	default:
		return actionTone{}
	}
}

func actionLabel(action, lang string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "deny":
		return choose(lang, "Deny", "Sperren (deny)")
	case "accept":
		return choose(lang, "Allow (accept)", "Erlauben (accept)")
	case "allow":
		return choose(lang, "Allow", "Erlauben (allow)")
	default:
		return action
	}
}

// record mirrors the website's publication details and finding cards. Field
// values remain complete and searchable, including when a grid row spans pages.
func (d *document) record(b block) {
	columns := 2
	if b.Layout == "finding" {
		columns = 1
	}
	d.recordHeading(b.Heading, b.Badge)
	if b.Text != "" {
		d.paragraph(b.Text, bodySize, false, lineHeight)
		d.y += 12
	}
	d.fieldGrid(b.Heading, b.Rows, columns)
	d.y += 8
}

func (d *document) recordHeading(title, badge string) {
	width := d.width - 2*margin
	badgeWidth := math.Min(170, width*.29)
	titleLines := d.wrap(title, width-badgeWidth-18, 12, true)
	badgeLines := d.wrap(badge, badgeWidth-14, 8.5, true)
	height := math.Max(float64(len(titleLines))*17, float64(len(badgeLines))*12+12)
	if height > 150 {
		// Exceptionally long names must not make a header taller than a page.
		d.ensure(70)
		d.paragraph(title, 12, true, 17)
		d.paragraph(badge, 8.5, true, 12)
		d.y += 10
		return
	}
	// Keep the title, metadata and the opening detail row together whenever
	// possible. Arbitrarily long object names still wrap and may span pages.
	d.ensure(math.Min(height+110, d.bottom-contentTop))
	d.y += 10
	d.pdf.SetStrokeColor(183, 204, 216)
	d.pdf.SetLineWidth(.7)
	d.pdf.Line(margin, d.y, d.width-margin, d.y)
	d.y += 12
	start := d.y
	for index, line := range titleLines {
		d.ensure(17)
		d.drawText(margin, d.y+12, line, 12, true, [3]uint8{15, 70, 96})
		d.y += 17
		if index == 0 && len(badgeLines) <= 3 {
			d.pdf.SetFillColor(236, 241, 245)
			d.pdf.RectFromUpperLeftWithStyle(d.width-margin-badgeWidth, start-2, badgeWidth, float64(len(badgeLines))*12+12, "F")
			for j, badgeLine := range badgeLines {
				d.drawText(d.width-margin-badgeWidth+7, start+11+float64(j)*12, badgeLine, 8.5, true, [3]uint8{61, 82, 97})
			}
		}
	}
	if len(badgeLines) > 3 {
		d.paragraph(badge, 8.5, true, 12)
	} else if d.y < start+height {
		d.y = start + height
	}
	d.y += 10
}

func (d *document) fieldGrid(title string, rows [][]string, columns int) {
	const gap = 22.0
	width := (d.width - 2*margin - float64(columns-1)*gap) / float64(columns)
	for first := 0; first < len(rows); first += columns {
		count := min(columns, len(rows)-first)
		labels, values := make([][]string, count), make([][]string, count)
		labelLines, valueLines := 1, 1
		for index := 0; index < count; index++ {
			row := rows[first+index]
			label, value := "", ""
			if len(row) > 0 {
				label = row[0]
			}
			if len(row) > 1 {
				value = row[1]
			}
			labels[index] = d.wrap(label, width, 8, true)
			values[index] = d.wrap(value, width, 9, false)
			labelLines = max(labelLines, len(labels[index]))
			valueLines = max(valueLines, len(values[index]))
		}
		labelHeight := float64(labelLines)*12 + 5
		height := labelHeight + float64(valueLines)*13 + 15
		if height <= d.bottom-contentTop && d.y+height > d.bottom {
			d.newPage()
			d.heading(title + choose(d.lang, " (continued)", " (Fortsetzung)"))
		}
		for offset := 0; offset < valueLines; {
			if !d.check() {
				return
			}
			available := int(math.Floor((d.bottom - d.y - labelHeight - 15) / 13))
			if available < 1 {
				d.newPage()
				d.heading(title + choose(d.lang, " (continued)", " (Fortsetzung)"))
				continue
			}
			lines := min(valueLines-offset, available)
			for index := 0; index < count; index++ {
				x := margin + float64(index)*(width+gap)
				for j, line := range labels[index] {
					d.drawText(x, d.y+8+float64(j)*12, line, 8, true, [3]uint8{65, 94, 112})
				}
				for j := 0; j < lines && offset+j < len(values[index]); j++ {
					d.drawText(x, d.y+labelHeight+9+float64(j)*13, values[index][offset+j], 9, false, [3]uint8{26, 45, 60})
				}
			}
			d.y += labelHeight + float64(lines)*13 + 15
			offset += lines
			if offset < valueLines {
				d.newPage()
				d.heading(title + choose(d.lang, " (continued)", " (Fortsetzung)"))
			}
		}
	}
}
