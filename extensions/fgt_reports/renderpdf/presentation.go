package renderpdf

import (
	"bytes"
	"context"
	"errors"
	"image"
	"math"
	"strconv"

	"github.com/signintech/gopdf"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

// renderOptions never crosses the export boundary. All user-facing data is
// carried in the separate, audience-specific content projection.
type renderOptions struct {
	language                   string
	landscape, cover, contents bool
	accent                     [3]uint8
	logo                       []byte
	logoMIME                   string
}

type chart struct {
	ID     string       `json:"id" xml:"id,attr"`
	Unit   string       `json:"unit" xml:"unit"`
	Points []chartPoint `json:"values" xml:"values>value"`
}

type chartPoint struct {
	Label string `json:"label" xml:"label"`
	Value int64  `json:"value" xml:"count"`
}

// boundedBuffer records its first error because some third-party writers do
// not consistently propagate output errors. It never retains a partial result
// as a successful report, and checks cancellation at each write.
type boundedBuffer struct {
	bytes.Buffer
	ctx context.Context
	err error
}

var errOutputLimit = errors.New("reports: output limit exceeded; report was not published")

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.err = b.ctx.Err(); b.err != nil {
		return 0, b.err
	}
	if len(p) > maxText-b.Len() {
		b.err = errOutputLimit
		return 0, b.err
	}
	return b.Buffer.Write(p)
}

// Implement StringWriter explicitly: embedding bytes.Buffer must not provide
// a path around the same size and cancellation checks.
func (b *boundedBuffer) WriteString(s string) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.err = b.ctx.Err(); b.err != nil {
		return 0, b.err
	}
	if len(s) > maxText-b.Len() {
		b.err = errOutputLimit
		return 0, b.err
	}
	return b.Buffer.WriteString(s)
}

func (d *document) coverPage(source reportmodel.Source) {
	d.newPage()
	d.y += 20
	d.logo(180, 70)
	if d.content.Company != "" {
		d.paragraph(d.content.Company, 14, true, 20)
		d.y += 16
	}
	d.paragraph(d.content.Title, 27, true, 34)
	d.y += 14
	d.paragraph(d.content.Identification, 13, false, 19)
	if d.content.Subtitle != "" {
		d.y += 10
		d.paragraph(d.content.Subtitle, 11, false, 17)
	}
	d.y += 24
	d.paragraph(choose(d.lang, "Configuration snapshot: ", "Konfigurationsstand: ")+formatTime(source.BackupAt, d.lang), 9.5, false, 14)
	d.paragraph(choose(d.lang, "Generated: ", "Erstellt: ")+formatTime(source.GeneratedAt, d.lang), 9.5, false, 14)
	d.y += 12
	d.paragraph(choose(d.lang,
		"Configuration-derived assessment. Operational performance and reachability have not been verified.",
		"Konfigurationsbasierte Bewertung. Betriebsleistung und Erreichbarkeit wurden nicht verifiziert."), 9.5, false, 14)
}

type contentsEntry struct {
	block, page int
	y           float64
	lines       []string
}

// Reserve exact title line heights first, then write page references after
// laying out the report. This keeps contents numbers correct without a
// separate whole-document render or a guessing-based page offset.
func (d *document) reserveContents(blocks []block) []contentsEntry {
	d.newPage()
	d.heading(choose(d.lang, "Contents", "Inhalt"))
	var entries []contentsEntry
	for index, b := range blocks {
		if !b.Contents || b.Heading == "" {
			continue
		}
		lines := d.wrap(b.Heading, d.width-2*margin-45, 10, false)
		height := float64(len(lines))*15 + 7
		d.ensure(height)
		entries = append(entries, contentsEntry{block: index, page: d.page, y: d.y, lines: lines})
		d.y += height
	}
	return entries
}

func (d *document) fillContents(entries []contentsEntry, starts map[int]int) {
	for _, entry := range entries {
		if !d.check() {
			return
		}
		if err := d.pdf.SetPage(entry.page); err != nil {
			d.err = err
			return
		}
		for n, line := range entry.lines {
			d.drawText(margin, entry.y+10+float64(n)*15, line, 10, false, [3]uint8{26, 45, 60})
		}
		label := strconv.Itoa(starts[entry.block])
		d.font(10, false)
		width, err := d.pdf.MeasureTextWidth(label)
		if err != nil {
			d.err = err
			return
		}
		d.drawText(d.width-margin-width, entry.y+10, label, 10, false, [3]uint8{26, 45, 60})
	}
}

// Every chart is followed by its exact value table in the shared projection.
// Bars are native PDF vectors; labels and values remain searchable text.
func (d *document) chart(c *chart) {
	maxValue := int64(0)
	for _, point := range c.Points {
		maxValue = max(maxValue, point.Value)
	}
	barWidth := (d.width - 2*margin) * 0.46
	labelWidth := (d.width - 2*margin) - barWidth - 55
	for _, point := range c.Points {
		lines := d.wrap(point.Label, labelWidth-8, 8.5, false)
		height := math.Max(23, float64(len(lines))*12+8)
		d.ensure(height)
		for n, line := range lines {
			d.drawText(margin, d.y+10+float64(n)*12, line, 8.5, false, [3]uint8{26, 45, 60})
		}
		x := margin + labelWidth
		d.pdf.SetFillColor(237, 241, 245)
		d.pdf.RectFromUpperLeftWithStyle(x, d.y+3, barWidth, 12, "F")
		if maxValue > 0 && point.Value > 0 {
			d.pdf.SetFillColor(d.options.accent[0], d.options.accent[1], d.options.accent[2])
			d.pdf.RectFromUpperLeftWithStyle(x, d.y+3, barWidth*float64(point.Value)/float64(maxValue), 12, "F")
		}
		d.drawText(x+barWidth+10, d.y+13, strconv.FormatInt(point.Value, 10), 8.5, true, [3]uint8{26, 45, 60})
		d.y += height
	}
	d.y += 8
}

func (d *document) logo(maxWidth, maxHeight float64) {
	if len(d.options.logo) == 0 || !d.check() {
		return
	}
	config, _, err := image.DecodeConfig(bytes.NewReader(d.options.logo))
	if err != nil {
		d.err = errors.New("reports: invalid logo")
		return
	}
	scale := math.Min(maxWidth/float64(config.Width), maxHeight/float64(config.Height))
	holder, err := gopdf.ImageHolderByBytes(d.options.logo)
	if err != nil {
		d.err = err
		return
	}
	d.err = d.pdf.ImageByHolder(holder, margin, d.y, &gopdf.Rect{W: float64(config.Width) * scale, H: float64(config.Height) * scale})
	d.y += float64(config.Height)*scale + 20
}

func (d *document) chartHeight(c *chart) float64 {
	labelWidth := (d.width-2*margin)*0.54 - 55
	height := 8.0
	for _, point := range c.Points {
		height += math.Max(23, float64(len(d.wrap(point.Label, labelWidth-8, 8.5, false)))*12+8)
	}
	return height
}
