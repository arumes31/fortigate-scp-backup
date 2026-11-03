package renderpdf

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"unicode"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

// Export serializes the same audience-specific content used by the PDF. It
// never reparses a configuration, queries a service, or serializes Assessment.
// Formats describe FortiSafe's own versioned contract, not a FortiAnalyzer
// import format. The caller provides the profile captured with the snapshot.
func Export(ctx context.Context, source reportmodel.Source, assessment reportmodel.Assessment, kind, format string, p reportmodel.Profile) ([]byte, error) {
	if format != "html" && format != "csv" && format != "json" && format != "xml" {
		return nil, errors.New("reports: unsupported export format")
	}
	view, options, hash, err := prepare(ctx, source, assessment, kind, p)
	if err != nil {
		return nil, err
	}
	doc := exportDocument{Schema: reportmodel.Version, Kind: kind, Language: options.language, ProfileRevision: hash,
		Source: exportSource{FirewallID: source.FirewallID, BackupID: source.BackupID, BackupAt: formatTime(source.BackupAt, options.language), GeneratedAt: formatTime(source.GeneratedAt, options.language), Checksum: checksum(source.Checksum, options.language)}, Report: view}
	out := &boundedBuffer{ctx: ctx}
	switch format {
	case "json":
		encoder := json.NewEncoder(out)
		encoder.SetEscapeHTML(false)
		err = encoder.Encode(doc)
	case "xml":
		_, err = out.WriteString(xml.Header)
		if err == nil {
			encoder := xml.NewEncoder(out)
			err = encoder.Encode(doc)
		}
	case "csv":
		err = writeCSV(out, doc)
	case "html":
		err = writeHTML(out, doc, options)
	}
	if err != nil {
		return nil, fmt.Errorf("reports: encode export: %w", err)
	}
	if out.err != nil {
		return nil, out.err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type exportDocument struct {
	XMLName         xml.Name     `json:"-" xml:"fortisafe-report"`
	Schema          string       `json:"schema" xml:"schema,attr"`
	Kind            string       `json:"kind" xml:"kind,attr"`
	Language        string       `json:"language" xml:"language,attr"`
	ProfileRevision string       `json:"profile_revision" xml:"profile-revision"`
	Source          exportSource `json:"source" xml:"source"`
	Report          content      `json:"report" xml:"report"`
}

type exportSource struct {
	FirewallID  int    `json:"firewall_id" xml:"firewall-id"`
	BackupID    int    `json:"backup_id" xml:"backup-id"`
	BackupAt    string `json:"backup_at" xml:"backup-at"`
	GeneratedAt string `json:"generated_at" xml:"generated-at"`
	Checksum    string `json:"checksum" xml:"checksum"`
}

// XML keeps table row boundaries explicit; a nested [][]string would otherwise
// flatten cells in encoding/xml and lose the row/column relationship.
func (b block) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	type row struct {
		Cells []string `xml:"cell"`
	}
	type xmlBlock struct {
		Heading string   `xml:"heading,omitempty"`
		Text    string   `xml:"text,omitempty"`
		Columns []string `xml:"columns>column,omitempty"`
		Rows    []row    `xml:"rows>row,omitempty"`
		Chart   *chart   `xml:"chart,omitempty"`
	}
	value := xmlBlock{Heading: b.Heading, Text: b.Text, Columns: b.Columns, Chart: b.Chart}
	for _, cells := range b.Rows {
		value.Rows = append(value.Rows, row{Cells: cells})
	}
	return encoder.EncodeElement(value, start)
}

func writeCSV(out *boundedBuffer, doc exportDocument) error {
	writer := csv.NewWriter(out)
	write := func(cells ...string) error {
		for i := range cells {
			cells[i] = csvSafe(cells[i])
		}
		return writer.Write(cells)
	}
	if err := write("section", "row", "column", "value"); err != nil {
		return err
	}
	metadata := [][]string{
		{"schema", doc.Schema}, {"kind", doc.Kind}, {"language", doc.Language}, {"profile_revision", doc.ProfileRevision},
		{"firewall_id", strconv.Itoa(doc.Source.FirewallID)}, {"backup_id", strconv.Itoa(doc.Source.BackupID)},
		{"backup_at", doc.Source.BackupAt}, {"generated_at", doc.Source.GeneratedAt}, {"checksum", doc.Source.Checksum},
		{"title", doc.Report.Title}, {"identification", doc.Report.Identification}, {"company", doc.Report.Company},
		{"subtitle", doc.Report.Subtitle}, {"introduction", doc.Report.Introduction}, {"footer", doc.Report.Footer},
	}
	for _, item := range metadata {
		if err := write("metadata", "", item[0], item[1]); err != nil {
			return err
		}
	}
	for index, b := range doc.Report.Blocks {
		section := b.Heading
		if section == "" {
			section = fmt.Sprintf("section-%d", index+1)
		}
		if b.Text != "" {
			if err := write(section, "", "text", b.Text); err != nil {
				return err
			}
		}
		if b.Chart != nil {
			if err := write(section, "", "chart_id", b.Chart.ID); err != nil {
				return err
			}
		}
		for row, cells := range b.Rows {
			for column, value := range cells {
				label := strconv.Itoa(column + 1)
				if column < len(b.Columns) {
					label = b.Columns[column]
				}
				if err := write(section, strconv.Itoa(row+1), label, value); err != nil {
					return err
				}
			}
		}
	}
	writer.Flush()
	return writer.Error()
}

// Protect every cell, including titles, labels and metadata. Spreadsheet apps
// may skip initial whitespace or invisible format marks before interpreting a
// formula. Account for those marks here even though the projection also strips
// them, and preserve the original value after a quote.
func csvSafe(s string) string {
	trimmed := strings.TrimLeftFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.In(r, unicode.Cf)
	})
	if strings.ContainsAny(s[:len(s)-len(trimmed)], "\t\r\n") {
		return "'" + s
	}
	if len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + s
	}
	return s
}

type htmlPoint struct {
	Label   string
	Value   int64
	Percent int
}
type htmlBlock struct {
	block
	Points []htmlPoint
	Index  int
}
type htmlDocument struct {
	exportDocument
	Blocks                               []htmlBlock
	Cover, Contents, Landscape           bool
	Accent                               template.CSS
	Logo                                 template.URL
	ContentsLabel, CountLabel, LogoLabel string
}

func writeHTML(out *boundedBuffer, doc exportDocument, options renderOptions) error {
	view := htmlDocument{exportDocument: doc, Cover: options.cover, Contents: options.contents, Landscape: options.landscape,
		ContentsLabel: choose(options.language, "Contents", "Inhalt"), CountLabel: choose(options.language, "Count", "Anzahl"), LogoLabel: choose(options.language, "Organization logo", "Organisationslogo")}
	// Values are generated solely from three parsed bytes and a canonical
	// in-memory PNG. User-controlled URLs, HTML and CSS never enter the view.
	view.Accent = template.CSS(fmt.Sprintf("#%02x%02x%02x", options.accent[0], options.accent[1], options.accent[2])) //nolint:gosec // Constant syntax plus parsed numeric bytes.
	if len(options.logo) > 0 {
		view.Logo = template.URL("data:" + options.logoMIME + ";base64," + base64.StdEncoding.EncodeToString(options.logo))
	} //nolint:gosec // Validated local PNG only.
	for index, b := range doc.Report.Blocks {
		h := htmlBlock{block: b, Index: index}
		if b.Chart != nil {
			maximum := int64(0)
			for _, p := range b.Chart.Points {
				maximum = max(maximum, p.Value)
			}
			for _, p := range b.Chart.Points {
				percent := 0
				if maximum > 0 {
					percent = int(float64(p.Value) / float64(maximum) * 100)
				}
				h.Points = append(h.Points, htmlPoint{Label: p.Label, Value: p.Value, Percent: percent})
			}
		}
		view.Blocks = append(view.Blocks, h)
	}
	return htmlReport.Execute(out, view)
}

var htmlReport = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Report.Title}}</title>
<style>:root{--accent:{{.Accent}};color-scheme:light}*{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,sans-serif;color:#1a2d3c;background:#eef2f5}main,header,nav,footer{max-width:1100px;margin:auto;padding:24px 32px;background:white}header{border-top:7px solid var(--accent)}h1,h2,h3{line-height:1.25;color:#143c50;overflow-wrap:anywhere}h1{font-size:30px}h2{font-size:22px;margin-top:32px}p,.text{white-space:pre-wrap;overflow-wrap:anywhere}.muted{color:#536673}.logo{max-width:180px;max-height:80px;object-fit:contain}.cover{min-height:65vh;padding-top:64px}.cover h1{font-size:38px}nav ol{padding-left:24px}nav a{color:#174b70}section{margin-bottom:28px}.scroll{overflow:auto;max-width:100%;border:1px solid #d5dfe6}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:10px 12px;text-align:left;vertical-align:top;border-bottom:1px solid #d5dfe6;white-space:pre-wrap;overflow-wrap:anywhere}th{background:#e2ecf2}tr:nth-child(even){background:#f6f8fa}.chart{padding:12px 0}.bar-row{display:grid;grid-template-columns:minmax(100px,1fr) minmax(80px,1.5fr) 60px;gap:12px;align-items:center;margin:9px 0}.bar-label{overflow-wrap:anywhere}.bar-track{height:14px;background:#edf1f5}.bar{display:block;height:100%;background:var(--accent)}footer{border-top:1px solid #d5dfe6;font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}@media(max-width:500px){main,header,nav,footer{padding:18px}h1{font-size:25px}.bar-row{grid-template-columns:minmax(70px,1fr) minmax(50px,1fr) 42px;font-size:12px}}@media print{body{background:white}main,header,nav,footer{max-width:none;padding:0}.cover,nav{break-after:page}.scroll{overflow:visible;border:0}thead{display:table-header-group}tr{break-inside:avoid}h2,h3{break-after:avoid}a{color:inherit;text-decoration:none}@page{size:A4{{if .Landscape}} landscape{{end}};margin:16mm}}
</style></head><body>
<header{{if .Cover}} class="cover"{{end}}>{{if .Logo}}<img class="logo" src="{{.Logo}}" alt="{{.LogoLabel}}">{{end}}{{if .Report.Company}}<p>{{.Report.Company}}</p>{{end}}<h1>{{.Report.Title}}</h1><p>{{.Report.Identification}}</p>{{if .Report.Subtitle}}<p>{{.Report.Subtitle}}</p>{{end}}<p class="muted">{{.Source.BackupAt}} · {{.Source.GeneratedAt}}</p>{{if .Report.Introduction}}<p>{{.Report.Introduction}}</p>{{end}}</header>
{{if .Contents}}<nav aria-label="{{.ContentsLabel}}"><h2>{{.ContentsLabel}}</h2><ol>{{range .Blocks}}{{if .Contents}}<li><a href="#section-{{.Index}}">{{.Heading}}</a></li>{{end}}{{end}}</ol></nav>{{end}}
<main>{{range .Blocks}}<section id="section-{{.Index}}">{{if .Heading}}<h2>{{.Heading}}</h2>{{end}}{{if .Text}}<p>{{.Text}}</p>{{end}}
{{if .Points}}<div class="chart" role="img" aria-label="{{.Heading}}; {{$.CountLabel}}">{{range .Points}}<div class="bar-row"><span class="bar-label">{{.Label}}</span><span class="bar-track"><span class="bar" style="width:{{.Percent}}%"></span></span><strong>{{.Value}}</strong></div>{{end}}</div>{{end}}
{{if .Columns}}<div class="scroll" tabindex="0" role="region" aria-label="{{.Heading}}"><table><thead><tr>{{range .Columns}}<th scope="col">{{.}}</th>{{end}}</tr></thead><tbody>{{range .Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>{{end}}</tbody></table></div>{{end}}</section>{{end}}</main>
<footer>{{.Report.Footer}}
Schema {{.Schema}} · {{.ProfileRevision}}</footer></body></html>`))
