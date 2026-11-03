package fgt_reports

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/extensions/fgt_reports/renderpdf"
)

func (e *Extension) exportHTML(w http.ResponseWriter, r *http.Request) {
	e.exportReport(w, r, "html", "text/html; charset=utf-8")
}
func (e *Extension) exportCSV(w http.ResponseWriter, r *http.Request) {
	e.exportReport(w, r, "csv", "text/csv; charset=utf-8")
}
func (e *Extension) exportJSON(w http.ResponseWriter, r *http.Request) {
	e.exportReport(w, r, "json", "application/json")
}
func (e *Extension) exportXML(w http.ResponseWriter, r *http.Request) {
	e.exportReport(w, r, "xml", "application/xml; charset=utf-8")
}

// Additional formats project the saved latest assessment and captured profile.
// They never rerun source selection, Graylog queries, or config analysis.
func (e *Extension) exportReport(w http.ResponseWriter, r *http.Request, format, mime string) {
	kind := chi.URLParam(r, "kind")
	switch kind {
	case "forwarding", "technical", "customer", "traffic":
	default:
		http.NotFound(w, r)
		return
	}
	source, err := e.requestedSource(r)
	if err != nil {
		reportError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	data, err := e.loadData(ctx, source.FirewallID)
	if err != nil {
		reportError(w, err)
		return
	}
	content, err := renderpdf.Export(ctx, data.Source, data.Assessment, kind, format, data.Profile)
	if err != nil {
		reportError(w, err)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="FortiSafe_%d_%s.%s"`, source.FirewallID, kind, format))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'")
	if _, err := w.Write(content); err != nil {
		e.logger.Warn("report export response write failed")
	}
	if e.logActivity != nil {
		user := ""
		if e.currentUser != nil {
			user = e.currentUser(r)
		}
		e.logActivity(user, "reports.downloaded", fmt.Sprintf("firewall_id=%d type=%s format=%s", source.FirewallID, kind, format))
	}
}
