// Package renderpdf renders the three FortiSafe reports without an external
// browser, network request or temporary plaintext configuration file.
package renderpdf

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"

	"github.com/signintech/gopdf"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

// Keep the font notice in the same embedded filesystem as the font bytes so
// it is distributed in the compiled application as well as in the source.
//
//go:embed fonts/DejaVuSans.ttf fonts/DejaVuSans-Bold.ttf fonts/LICENSE.txt
var fontFiles embed.FS

const (
	pageWidth  = 595.28
	pageHeight = 841.89
	margin     = 42.0
	contentTop = 65.0
	contentEnd = 785.0
	bodySize   = 9.5
	lineHeight = 14.0
	cellPad    = 7.0
	maxPages   = 1000
	maxText    = 16 << 20
)

type block struct {
	Heading string
	Text    string
	Columns []string
	Widths  []float64
	Rows    [][]string
}

// content is a detached presentation model. In particular, customer content
// never retains the original assessment, raw findings, or technical evidence.
type content struct {
	Title          string
	Identification string
	Footer         string
	Blocks         []block
}

type document struct {
	pdf       *gopdf.GoPdf
	ctx       context.Context
	content   content
	lang      string
	y         float64
	page      int
	err       error
	textBytes int
	glyphs    map[rune]bool
}

// Render returns a complete PDF or an error; it never truncates a report to
// meet a page/resource limit. lang must be en or de, and kind must be one of
// forwarding, technical, or customer. Source times are rendered with offsets.
func Render(ctx context.Context, source reportmodel.Source, assessment reportmodel.Assessment, kind, lang string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("reports: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lang != "en" && lang != "de" {
		return nil, errors.New("reports: unsupported language")
	}
	if kind != "forwarding" && kind != "technical" && kind != "customer" {
		return nil, errors.New("reports: unsupported report type")
	}
	if err := validateProjection(ctx, source, assessment, kind); err != nil {
		return nil, err
	}
	view := project(source, assessment, kind, lang)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d := &document{pdf: &gopdf.GoPdf{}, ctx: ctx, content: view, lang: lang, glyphs: make(map[rune]bool)}
	d.pdf.Start(gopdf.Config{PageSize: gopdf.Rect{W: pageWidth, H: pageHeight}})
	regularFont, err := fontFiles.ReadFile("fonts/DejaVuSans.ttf")
	if err != nil {
		return nil, err
	}
	boldFont, err := fontFiles.ReadFile("fonts/DejaVuSans-Bold.ttf")
	if err != nil {
		return nil, err
	}
	if err := d.pdf.AddTTFFontData("sans", regularFont); err != nil {
		return nil, fmt.Errorf("reports: embed regular font: %w", err)
	}
	if err := d.pdf.AddTTFFontData("bold", boldFont); err != nil {
		return nil, fmt.Errorf("reports: embed bold font: %w", err)
	}
	d.pdf.SetInfo(gopdf.PdfInfo{
		Title: view.Title, Author: "FortiSafe", Creator: "FortiSafe Reports",
		Subject: "Saved configuration assessment", CreationDate: source.GeneratedAt,
	})
	d.newPage()
	d.paragraph(view.Title, 24, true, 31)
	d.paragraph(view.Identification, 11, false, 17)
	d.y += 12
	for _, b := range view.Blocks {
		if !d.check() {
			break
		}
		if b.Heading != "" {
			if len(b.Columns) > 0 && b.Text == "" {
				lines := d.wrap(b.Heading, pageWidth-2*margin, 13, true)
				d.ensure(17 + float64(len(lines))*18 + d.tableOpeningHeight(b.Columns, b.Widths, b.Rows))
			}
			d.heading(b.Heading)
		}
		if b.Text != "" {
			d.paragraph(b.Text, bodySize, false, lineHeight)
			d.y += 6
		}
		if len(b.Columns) > 0 {
			d.table(b.Heading, b.Columns, b.Widths, b.Rows)
			d.y += 10
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	// Add page totals only after pagination, without putting the source model
	// or any hidden payload in metadata, attachments, or outline titles.
	for page := 1; page <= d.page; page++ {
		if err := d.pdf.SetPage(page); err != nil {
			return nil, fmt.Errorf("reports: footer page: %w", err)
		}
		d.pdf.SetStrokeColor(209, 218, 225)
		d.pdf.SetLineWidth(0.5)
		d.pdf.Line(margin, 803, pageWidth-margin, 803)
		d.drawText(margin, 819, view.Footer, 7.2, false, [3]uint8{87, 102, 115})
		label := fmt.Sprintf("%s %d / %d", choose(lang, "Page", "Seite"), page, d.page)
		d.font(7.2, false)
		width, err := d.pdf.MeasureTextWidth(label)
		if err != nil {
			return nil, err
		}
		d.drawText(pageWidth-margin-width, 819, label, 7.2, false, [3]uint8{87, 102, 115})
	}
	if d.err != nil {
		return nil, d.err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := d.pdf.GetBytesPdfReturnErr()
	if err != nil {
		return nil, fmt.Errorf("reports: encode PDF: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func (d *document) check() bool {
	if d.err == nil {
		d.err = d.ctx.Err()
	}
	return d.err == nil
}

func (d *document) font(size float64, bold bool) {
	if !d.check() {
		return
	}
	family := "sans"
	if bold {
		family = "bold"
	}
	d.err = d.pdf.SetFont(family, "", size)
}

func (d *document) newPage() {
	if !d.check() {
		return
	}
	if d.page >= maxPages {
		d.err = errors.New("reports: PDF page limit exceeded; report was not published")
		return
	}
	d.pdf.AddPage()
	d.page++
	d.pdf.SetFillColor(15, 46, 66)
	d.pdf.RectFromUpperLeftWithStyle(0, 0, pageWidth, 45, "F")
	d.drawText(margin, 29, "FortiSafe", 14, true, [3]uint8{255, 255, 255})
	d.drawText(405, 28, choose(d.lang, "CONFIGURATION REVIEW", "KONFIGURATIONSPRÜFUNG"), 7, true, [3]uint8{174, 217, 233})
	d.y = contentTop
}

func (d *document) ensure(height float64) {
	if d.y+height > contentEnd {
		d.newPage()
	}
}

// clean removes control characters that could reorder or hide a value. A
// missing font glyph is spelled out as a Unicode code point, never dropped.
func (d *document) clean(text string) string {
	d.textBytes += len(text)
	if d.textBytes > maxText {
		d.err = errors.New("reports: PDF text limit exceeded; report was not published")
		return ""
	}
	d.font(bodySize, false)
	var out strings.Builder
	for _, r := range text {
		if r == '\t' {
			out.WriteByte(' ')
			continue
		}
		if r == '\n' {
			out.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			continue
		}
		present, known := d.glyphs[r]
		if !known {
			var err error
			present, err = d.pdf.IsCurrFontContainGlyph(r)
			if err != nil {
				d.err = err
				return ""
			}
			d.glyphs[r] = present
		}
		if present {
			out.WriteRune(r)
		} else {
			fmt.Fprintf(&out, "[U+%04X]", r)
		}
	}
	return out.String()
}

func (d *document) wrap(text string, width, size float64, bold bool) []string {
	text = d.clean(text)
	if !d.check() {
		return nil
	}
	if strings.TrimSpace(text) == "" {
		return []string{"-"}
	}
	d.font(size, bold)
	lines, err := d.pdf.SplitTextWithWordWrap(text, width)
	if err != nil {
		d.err = err
	}
	return lines
}

func (d *document) drawText(x, baseline float64, text string, size float64, bold bool, color [3]uint8) {
	if !d.check() {
		return
	}
	d.font(size, bold)
	d.pdf.SetTextColor(color[0], color[1], color[2])
	d.pdf.SetXY(x, baseline)
	d.err = d.pdf.Text(text)
}

func (d *document) paragraph(text string, size float64, bold bool, height float64) {
	for _, line := range d.wrap(text, pageWidth-2*margin, size, bold) {
		d.ensure(height)
		d.drawText(margin, d.y+size, line, size, bold, [3]uint8{26, 45, 60})
		d.y += height
	}
}

func (d *document) heading(text string) {
	lines := d.wrap(text, pageWidth-2*margin, 13, true)
	d.ensure(float64(len(lines))*18 + 45)
	d.y += 10
	for _, line := range lines {
		d.drawText(margin, d.y+13, line, 13, true, [3]uint8{15, 70, 96})
		d.y += 18
	}
	d.y += 7
}

// table repeats its column headings and splits oversized rows across pages.
// No row is clipped, and long unbroken object names wrap at glyph boundaries.
func (d *document) table(title string, columns []string, relativeWidths []float64, rows [][]string) {
	if len(columns) == 0 || !d.check() {
		return
	}
	widths := tableWidths(len(columns), relativeWidths)
	d.ensure(d.tableOpeningHeight(columns, relativeWidths, rows))
	headers := make([][]string, len(columns))
	headerLines := 1
	for i, title := range columns {
		headers[i] = d.wrap(title, widths[i]-2*cellPad, 8.5, true)
		headerLines = max(headerLines, len(headers[i]))
	}
	headerHeight := float64(headerLines)*12 + 2*cellPad
	printHeader := func() {
		d.ensure(headerHeight + 2*cellPad + 12)
		d.pdf.SetFillColor(226, 236, 242)
		d.pdf.RectFromUpperLeftWithStyle(margin, d.y, pageWidth-2*margin, headerHeight, "F")
		x := margin
		for i := range columns {
			for line, value := range headers[i] {
				d.drawText(x+cellPad, d.y+cellPad+8.5+float64(line)*12, value, 8.5, true, [3]uint8{15, 55, 78})
			}
			x += widths[i]
		}
		d.y += headerHeight
	}
	continueTable := func() {
		d.newPage()
		if title != "" {
			d.heading(title + choose(d.lang, " (continued)", " (Fortsetzung)"))
		}
		printHeader()
	}
	printHeader()
	for rowIndex, row := range rows {
		if !d.check() {
			return
		}
		cells := make([][]string, len(columns))
		rowLines := 1
		for i := range columns {
			value := ""
			if i < len(row) {
				value = row[i]
			}
			cells[i] = d.wrap(value, widths[i]-2*cellPad, 8.5, false)
			rowLines = max(rowLines, len(cells[i]))
		}
		// A normal-sized row stays together whenever it can fit on a fresh page.
		rowHeight := float64(rowLines)*12 + 2*cellPad
		if rowHeight <= contentEnd-contentTop-headerHeight && d.y+rowHeight > contentEnd {
			continueTable()
		}
		for offset := 0; offset < rowLines; {
			if !d.check() {
				return
			}
			available := int(math.Floor((contentEnd - d.y - 2*cellPad) / 12))
			if available < 1 {
				continueTable()
				continue
			}
			count := min(rowLines-offset, available)
			height := float64(count)*12 + 2*cellPad
			if rowIndex%2 == 0 {
				d.pdf.SetFillColor(246, 248, 250)
				d.pdf.RectFromUpperLeftWithStyle(margin, d.y, pageWidth-2*margin, height, "F")
			}
			x := margin
			for i, lines := range cells {
				for line := 0; line < count && offset+line < len(lines); line++ {
					d.drawText(x+cellPad, d.y+cellPad+8.5+float64(line)*12, lines[offset+line], 8.5, false, [3]uint8{26, 45, 60})
				}
				x += widths[i]
			}
			d.pdf.SetStrokeColor(218, 226, 232)
			d.pdf.SetLineWidth(0.35)
			d.pdf.Line(margin, d.y+height, pageWidth-margin, d.y+height)
			d.y += height
			offset += count
			if offset < rowLines {
				continueTable()
			}
		}
	}
}

func tableWidths(count int, relativeWidths []float64) []float64 {
	widths := make([]float64, count)
	total := 0.0
	for i := range widths {
		widths[i] = 1
		if len(relativeWidths) == count && relativeWidths[i] > 0 {
			widths[i] = relativeWidths[i]
		}
		total += widths[i]
	}
	for i := range widths {
		widths[i] = widths[i] / total * (pageWidth - 2*margin)
	}
	return widths
}

// Keep the initial table heading with data. Very tall rows are allowed to
// split, so reserve only a useful first portion of such a row.
func (d *document) tableOpeningHeight(columns []string, relativeWidths []float64, rows [][]string) float64 {
	widths := tableWidths(len(columns), relativeWidths)
	headerLines, rowLines := 1, 1
	for i, column := range columns {
		headerLines = max(headerLines, len(d.wrap(column, widths[i]-2*cellPad, 8.5, true)))
		if len(rows) > 0 && i < len(rows[0]) {
			rowLines = max(rowLines, len(d.wrap(rows[0][i], widths[i]-2*cellPad, 8.5, false)))
		}
	}
	return float64(headerLines)*12 + 2*cellPad + math.Min(float64(rowLines)*12+2*cellPad, 250)
}

func choose(lang, en, de string) string {
	if lang == "de" {
		return de
	}
	return en
}
