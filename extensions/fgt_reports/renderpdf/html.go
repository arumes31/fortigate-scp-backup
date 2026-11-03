package renderpdf

import (
	"html/template"
	"strings"
)

var htmlReport = template.Must(template.New("report").Funcs(template.FuncMap{
	"actionClass": func(actions []string, index int) string {
		if index < 0 || index >= len(actions) {
			return ""
		}
		return toneForAction(actions[index]).Class
	},
	"firstLine":  func(value string) string { first, _, _ := strings.Cut(value, "\n"); return first },
	"otherLines": func(value string) string { _, rest, _ := strings.Cut(value, "\n"); return rest },
}).Parse(`<!doctype html>
<html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Report.Title}}</title>
<style>
:root{--accent:{{.Accent}};color-scheme:light}*{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,sans-serif;color:#1a2d3c;background:#eef2f5}main,header,nav,footer{max-width:1280px;margin:auto;padding:24px 32px;background:#fff}header{border-top:7px solid var(--accent)}h1,h2,h3{line-height:1.3;color:#143c50;overflow-wrap:anywhere}h1{font-size:30px}h2{font-size:21px;margin:0 0 18px}p,.text{white-space:pre-wrap;overflow-wrap:anywhere}.muted{color:#536673}.logo{max-width:180px;max-height:80px;object-fit:contain}.cover{min-height:65vh;padding-top:64px}.cover h1{font-size:38px}nav ol{padding-left:24px}nav a{color:#174b70}section{margin-bottom:32px}.record-header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:14px}.record-header h2{margin:0}.badge{display:inline-block;flex:none;border:1px solid #b9cad4;border-radius:3px;padding:4px 9px;font-size:12px;font-weight:600;color:#3d5261;background:#ecf1f5;max-width:35%;overflow-wrap:anywhere}.publication,.finding{border-top:1px solid #b7ccd8;padding-top:22px}.publication>.text{color:#536673;margin-bottom:24px}.details{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:32px;row-gap:18px;margin:0}.details>div{min-width:0}.details dt{font-size:12px;color:#415e70;font-weight:600;margin-bottom:5px}.details dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.finding .details{grid-template-columns:1fr}.scroll{overflow:auto;max-width:100%;border:1px solid #d5dfe6}table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:10px 12px;text-align:left;vertical-align:top;border-bottom:1px solid #d5dfe6;white-space:pre-wrap;overflow-wrap:anywhere}th{background:#e2ecf2;color:#0f374e;font-weight:650}tbody tr:nth-child(even){background:#f6f8fa}.policies table{min-width:900px;table-layout:fixed}.action{display:inline-block;padding:3px 7px;border-radius:3px;border:1px solid #bcc9d2;font-weight:700;margin-bottom:5px}.action-deny{color:#991b1b;background:#fee2e2;border-color:#dc9696}.action-allow{color:#166534;background:#dcfce7;border-color:#8bc49f}.inventory summary{cursor:pointer;color:#143c50;font-size:17px;font-weight:650;padding:12px 0}.inventory summary .badge{margin-left:8px}.chart{display:grid;gap:8px;margin:18px 0}.bar-row{display:grid;grid-template-columns:minmax(130px,1fr) 3fr 70px;gap:12px;align-items:center}.bar-label{overflow-wrap:anywhere}.bar-track{height:16px;background:#e7edf1}.bar{height:100%;background:var(--accent)}footer{border-top:1px solid #d5dfe6;font-size:12px;color:#536673;overflow-wrap:anywhere;white-space:pre-wrap}
@media(max-width:700px){main,header,nav,footer{padding:20px 16px}h1{font-size:26px}.record-header{flex-direction:column;gap:10px}.badge{max-width:100%}.details{grid-template-columns:1fr}.bar-row{grid-template-columns:1fr 2fr 50px;gap:8px}.scroll{margin-bottom:12px}}
@media print{body{background:#fff;font-size:10pt}main,header,nav,footer{max-width:none;padding:16px 0}.cover{break-after:page;min-height:0}.scroll{overflow:visible}table{font-size:8pt}.policies table{min-width:0}thead{display:table-header-group}tr{break-inside:avoid}h2,summary,.record-header{break-after:avoid}.chart{break-inside:avoid}nav{break-after:page}@page{size:A4{{if .Landscape}} landscape{{end}};margin:16mm}}
</style></head><body>
<header{{if .Cover}} class="cover"{{end}}>{{if .Logo}}<img class="logo" src="{{.Logo}}" alt="{{.LogoLabel}}">{{end}}<h1>{{.Report.Title}}</h1><p>{{.Report.Identification}}</p>{{if .Report.Company}}<p>{{.Report.Company}}</p>{{end}}{{if .Report.Subtitle}}<p>{{.Report.Subtitle}}</p>{{end}}{{if .Report.Introduction}}<p>{{.Report.Introduction}}</p>{{end}}</header>
{{if .Contents}}<nav aria-label="{{.ContentsLabel}}"><h2>{{.ContentsLabel}}</h2><ol>{{range .Blocks}}{{if .Contents}}<li><a href="#section-{{.Index}}">{{.Heading}}</a></li>{{end}}{{end}}</ol></nav>{{end}}
<main>{{range .Blocks}}{{$block := .}}<section id="section-{{.Index}}" class="{{.Layout}}">
{{if eq .Layout "inventory"}}<details open><summary>{{.Heading}} <span class="badge">{{.Badge}}</span></summary>{{else}}{{if .Heading}}<div class="record-header"><h2>{{.Heading}}</h2>{{if .Badge}}<span class="badge">{{.Badge}}</span>{{end}}</div>{{end}}{{end}}
{{if .Text}}<p class="text">{{.Text}}</p>{{end}}
{{if .Points}}<div class="chart" role="img" aria-label="{{.Heading}}">{{range .Points}}<div class="bar-row"><span class="bar-label">{{.Label}}</span><div class="bar-track"><div class="bar" style="width:{{.Percent}}%"></div></div><strong>{{.Value}}</strong></div>{{end}}</div>{{end}}
{{if or (eq .Layout "publication") (eq .Layout "finding")}}<dl class="details">{{range .Rows}}<div><dt>{{index . 0}}</dt><dd>{{index . 1}}</dd></div>{{end}}</dl>
{{else}}{{if .Columns}}<div class="scroll" tabindex="0" role="region" aria-label="{{.Heading}}"><table>{{if eq .Layout "policies"}}<colgroup><col style="width:18%"><col style="width:15%"><col style="width:24%"><col style="width:19%"><col style="width:24%"></colgroup>{{end}}<thead><tr>{{range .Columns}}<th scope="col">{{.}}</th>{{end}}</tr></thead><tbody>{{range $rowIndex,$row := .Rows}}<tr>{{range $columnIndex,$value := $row}}<td>{{if and (eq $block.Layout "policies") (eq $columnIndex 1)}}<span class="action {{actionClass $block.Actions $rowIndex}}">{{firstLine $value}}</span><div class="text">{{otherLines $value}}</div>{{else}}{{$value}}{{end}}</td>{{end}}</tr>{{end}}</tbody></table></div>{{end}}{{end}}
{{if eq .Layout "inventory"}}</details>{{end}}</section>{{end}}</main>
<footer>{{.Report.Footer}}
Schema {{.Schema}} · {{.ProfileRevision}}</footer></body></html>`))
