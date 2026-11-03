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
	Heading  string     `json:"heading,omitempty" xml:"heading,omitempty"`
	Text     string     `json:"text,omitempty" xml:"text,omitempty"`
	Columns  []string   `json:"columns,omitempty" xml:"columns>column,omitempty"`
	Widths   []float64  `json:"-" xml:"-"`
	Rows     [][]string `json:"rows,omitempty" xml:"-"`
	Chart    *chart     `json:"chart,omitempty" xml:"chart,omitempty"`
	Contents bool       `json:"-" xml:"-"`
}

// content is a detached presentation model. In particular, customer content
// never retains the original assessment, raw findings, or technical evidence.
type content struct {
	Title          string  `json:"title" xml:"title"`
	Identification string  `json:"identification" xml:"identification"`
	Company        string  `json:"company,omitempty" xml:"company,omitempty"`
	Subtitle       string  `json:"subtitle,omitempty" xml:"subtitle,omitempty"`
	Introduction   string  `json:"introduction,omitempty" xml:"introduction,omitempty"`
	Footer         string  `json:"footer" xml:"footer"`
	Blocks         []block `json:"sections" xml:"sections>section"`
}

type document struct {
	pdf           *gopdf.GoPdf
	ctx           context.Context
	content       content
	lang          string
	y             float64
	page          int
	err           error
	textBytes     int
	glyphs        map[rune]bool
	width, height float64
	options       renderOptions
	bottom        float64
	footerLines   []string
}

// Render returns a complete PDF or an error; it never truncates a report to
// meet a page/resource limit. lang must be en or de, and kind must be one of
// forwarding, technical, or customer. Source times are rendered with offsets.
func Render(ctx context.Context, source reportmodel.Source, assessment reportmodel.Assessment, kind, lang string) ([]byte, error) {
	if lang != "en" && lang != "de" {
		return nil, errors.New("reports: unsupported language")
	}
	return RenderWithProfile(ctx, source, assessment, kind, reportmodel.DefaultProfile(lang))
}

func renderDocument(ctx context.Context, source reportmodel.Source, view content, options renderOptions) ([]byte, error) {
	d := &document{pdf: &gopdf.GoPdf{}, ctx: ctx, content: view, lang: options.language,
		glyphs: make(map[rune]bool), width: pageWidth, height: pageHeight, options: options}
	if options.landscape {
		d.width, d.height = pageHeight, pageWidth
	}
	d.pdf.Start(gopdf.Config{PageSize: gopdf.Rect{W: d.width, H: d.height}})
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
	d.footerLines = d.wrap(view.Footer, d.width-2*margin-65, 7.2, false)
	d.bottom = d.height - 57 - float64(max(0, len(d.footerLines)-1))*10
	d.pdf.SetInfo(gopdf.PdfInfo{Title: view.Title, Author: "FortiSafe", Creator: "FortiSafe Reports",
		Subject: "Saved configuration and captured log observations", CreationDate: source.GeneratedAt})
	if options.cover {
		d.coverPage(source)
	}
	var contents []contentsEntry
	if options.contents {
		contents = d.reserveContents(view.Blocks)
	}
	d.newPage()
	if !options.cover {
		d.logo(120, 40)
	}
	d.paragraph(view.Title, 24, true, 31)
	d.paragraph(view.Identification, 11, false, 17)
	for _, line := range []string{view.Company, view.Subtitle, view.Introduction} {
		if line != "" {
			d.y += 6
			d.paragraph(line, bodySize, false, lineHeight)
		}
	}
	d.y += 12
	starts := make(map[int]int, len(contents))
	for index, b := range view.Blocks {
		if !d.check() {
			break
		}
		if len(b.Columns) > 0 {
			opening := d.tableOpeningHeight(b.Columns, b.Widths, b.Rows)
			if b.Heading != "" {
				opening += 17 + float64(len(d.wrap(b.Heading, d.width-2*margin, 13, true)))*18
			}
			if b.Text != "" {
				opening += 6 + float64(len(d.wrap(b.Text, d.width-2*margin, bodySize, false)))*lineHeight
			}
			if b.Chart != nil {
				opening += d.chartHeight(b.Chart)
			}
			d.ensure(math.Min(opening, d.bottom-contentTop))
		}
		if b.Heading != "" {
			d.heading(b.Heading)
		}
		starts[index] = d.page
		if b.Text != "" {
			d.paragraph(b.Text, bodySize, false, lineHeight)
			d.y += 6
		}
		if b.Chart != nil {
			d.chart(b.Chart)
		}
		if len(b.Columns) > 0 {
			d.table(b.Heading, b.Columns, b.Widths, b.Rows)
			d.y += 10
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	d.fillContents(contents, starts)
	for page := 1; page <= d.page; page++ {
		if err := d.pdf.SetPage(page); err != nil {
			return nil, fmt.Errorf("reports: footer page: %w", err)
		}
		d.pdf.SetStrokeColor(209, 218, 225)
		d.pdf.SetLineWidth(0.5)
		d.pdf.Line(margin, d.bottom+18, d.width-margin, d.bottom+18)
		for index, line := range d.footerLines {
			d.drawText(margin, d.bottom+34+float64(index)*10, line, 7.2, false, [3]uint8{87, 102, 115})
		}
		label := fmt.Sprintf("%s %d / %d", choose(d.lang, "Page", "Seite"), page, d.page)
		d.font(7.2, false)
		width, err := d.pdf.MeasureTextWidth(label)
		if err != nil {
			return nil, err
		}
		d.drawText(d.width-margin-width, d.height-23, label, 7.2, false, [3]uint8{87, 102, 115})
	}
	if d.err != nil {
		return nil, d.err
	}
	out := &boundedBuffer{ctx: ctx}
	if _, err := d.pdf.WriteTo(out); err != nil {
		return nil, fmt.Errorf("reports: encode PDF: %w", err)
	}
	// gopdf currently does not propagate all writer errors from object encoding.
	if out.err != nil {
		return nil, out.err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
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
	d.pdf.RectFromUpperLeftWithStyle(0, 0, d.width, 45, "F")
	d.drawText(margin, 29, "FortiSafe", 14, true, [3]uint8{255, 255, 255})
	d.drawText(d.width-190, 28, choose(d.lang, "FIREWALL REPORTS", "FIREWALL-BERICHTE"), 7, true, [3]uint8{174, 217, 233})
	d.pdf.SetFillColor(d.options.accent[0], d.options.accent[1], d.options.accent[2])
	d.pdf.RectFromUpperLeftWithStyle(0, 43, d.width, 3, "F")
	d.y = contentTop
}

func (d *document) ensure(height float64) {
	if d.y+height > d.bottom {
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
		if !d.check() {
			return ""
		}
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
	if !d.check() {
		return nil
	}
	lines, err := wrapText(d.ctx, text, width, d.pdf.MeasureTextWidth)
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
	for _, line := range d.wrap(text, d.width-2*margin, size, bold) {
		d.ensure(height)
		d.drawText(margin, d.y+size, line, size, bold, [3]uint8{26, 45, 60})
		d.y += height
	}
}

func (d *document) heading(text string) {
	lines := d.wrap(text, d.width-2*margin, 13, true)
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
	widths := d.tableWidths(len(columns), relativeWidths)
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
		d.pdf.RectFromUpperLeftWithStyle(margin, d.y, d.width-2*margin, headerHeight, "F")
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
		if rowHeight <= d.bottom-contentTop-headerHeight && d.y+rowHeight > d.bottom {
			continueTable()
		}
		for offset := 0; offset < rowLines; {
			if !d.check() {
				return
			}
			available := int(math.Floor((d.bottom - d.y - 2*cellPad) / 12))
			if available < 1 {
				continueTable()
				continue
			}
			count := min(rowLines-offset, available)
			height := float64(count)*12 + 2*cellPad
			if rowIndex%2 == 0 {
				d.pdf.SetFillColor(246, 248, 250)
				d.pdf.RectFromUpperLeftWithStyle(margin, d.y, d.width-2*margin, height, "F")
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
			d.pdf.Line(margin, d.y+height, d.width-margin, d.y+height)
			d.y += height
			offset += count
			if offset < rowLines {
				continueTable()
			}
		}
	}
}

func (d *document) tableWidths(count int, relativeWidths []float64) []float64 {
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
		widths[i] = widths[i] / total * (d.width - 2*margin)
	}
	return widths
}

// Keep the initial table heading with data. Very tall rows are allowed to
// split, so reserve only a useful first portion of such a row.
func (d *document) tableOpeningHeight(columns []string, relativeWidths []float64, rows [][]string) float64 {
	widths := d.tableWidths(len(columns), relativeWidths)
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
