package fgt_reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

type reportRow struct {
	FirewallID   int
	Firewall     string
	LatestBackup string
	Status       string
	Error        string
	Ready        bool
	Limited      bool
	Stale        bool
	ReportBackup string
	Generated    string
	ProfileName  string
	NextDue      string
	TrafficReady bool
}

type indexData struct {
	Base     webui.BaseData
	Rows     []reportRow
	Language string
}

type detailData struct {
	Base          webui.BaseData
	Report        reportData
	Selection     reportmodel.Selection
	Stale         bool
	BackupTime    string
	GeneratedTime string
}

func displayTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func (e *Extension) index(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	sources, err := e.listSources(ctx)
	if err != nil {
		http.Error(w, "Report sources are temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	view := indexData{Base: e.pageBase(r, "Reports", "reports"), Language: e.cfg.ReportsLanguage}
	for _, source := range sources {
		row := reportRow{FirewallID: source.FirewallID, Firewall: source.Firewall, LatestBackup: displayTime(source.BackupAt), Status: "queued"}
		profile, err := e.getProfile(ctx, source.FirewallID)
		if err != nil {
			reportError(w, err)
			return
		}
		row.ProfileName, row.NextDue = profile.Profile.Name, displayTime(profile.NextDue)
		var publishedID, backupNS, generatedNS int64
		var generation string
		var checksum string
		var limited int
		err = e.db.QueryRowContext(ctx, `SELECT t.status,t.error,COALESCE(l.backup_id,0),COALESCE(l.backup_ns,0),
 COALESCE(l.generated_ns,0),COALESCE(l.generation,''),COALESCE(l.checksum,''),COALESCE(l.limited,0),COALESCE(length(l.traffic),0)>0
 FROM report_targets t LEFT JOIN report_latest l USING(firewall_id) WHERE t.firewall_id=?`, source.FirewallID).
			Scan(&row.Status, &row.Error, &publishedID, &backupNS, &generatedNS, &generation, &checksum, &limited, &row.TrafficReady)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Report status is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		row.Ready = publishedID > 0
		row.Limited = limited != 0
		if row.Ready {
			row.ReportBackup = displayTime(time.Unix(0, backupNS))
			row.Generated = displayTime(time.Unix(0, generatedNS))
			row.Stale = int(publishedID) != source.BackupID || backupNS != source.BackupAt.UnixNano() || generation != profileGeneration(profile.Profile) || (source.Checksum != "" && checksum != source.Checksum)
		}
		view.Rows = append(view.Rows, row)
	}
	if err := e.page.RenderHTTP(w, view); err != nil {
		e.logger.Error("reports page rendering failed")
		http.Error(w, "Unable to render reports", http.StatusInternalServerError)
	}
}

// Resolve against the current host catalog on every read. Deleted firewalls
// cannot retain a downloadable report between deletion and reconciliation.
func (e *Extension) requestedSource(r *http.Request) (reportmodel.Source, error) {
	id, err := strconv.Atoi(chi.URLParam(r, "firewallID"))
	if err != nil || id <= 0 {
		return reportmodel.Source{}, sql.ErrNoRows
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	sources, err := e.listSources(ctx)
	if err != nil {
		return reportmodel.Source{}, err
	}
	for _, source := range sources {
		if source.FirewallID == id {
			return source, nil
		}
	}
	return reportmodel.Source{}, sql.ErrNoRows
}

func (e *Extension) loadData(ctx context.Context, firewallID int) (reportData, error) {
	var data reportData
	var encrypted []byte
	if err := e.db.QueryRowContext(ctx, "SELECT assessment FROM report_latest WHERE firewall_id=?", firewallID).Scan(&encrypted); err != nil {
		return data, err
	}
	if len(encrypted) > maxReportSetBytes {
		return data, errors.New("stored report exceeds limit")
	}
	plain, err := e.cipher.Decrypt(encrypted)
	if err != nil {
		return data, err
	}
	err = json.Unmarshal(plain, &data)
	clear(plain)
	if err == nil && data.Profile.Schema == 0 {
		data.Profile = reportmodel.DefaultProfile(data.Language)
	}
	return data, err
}

func reportError(w http.ResponseWriter, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Report not available", http.StatusNotFound)
		return
	}
	http.Error(w, "Report is temporarily unavailable", http.StatusServiceUnavailable)
}

func (e *Extension) detail(w http.ResponseWriter, r *http.Request) {
	source, err := e.requestedSource(r)
	if err != nil {
		reportError(w, err)
		return
	}
	data, err := e.loadData(r.Context(), source.FirewallID)
	if err != nil {
		reportError(w, err)
		return
	}
	profile, err := e.getProfile(r.Context(), source.FirewallID)
	if err != nil {
		reportError(w, err)
		return
	}
	selected, selection := reportmodel.Select(data.Assessment, data.Profile)
	data.Assessment = selected
	view := detailData{Base: e.pageBase(r, "Reports", "reports"), Report: data, Selection: selection,
		Stale:      source.BackupID != data.Source.BackupID || !source.BackupAt.Equal(data.Source.BackupAt) || data.Version != reportmodel.Version || profileGeneration(data.Profile) != profileGeneration(profile.Profile) || (source.Checksum != "" && source.Checksum != data.Source.Checksum),
		BackupTime: displayTime(data.Source.BackupAt), GeneratedTime: displayTime(data.Source.GeneratedAt)}
	if err := e.detailPage.RenderHTTP(w, view); err != nil {
		e.logger.Error("report detail rendering failed")
		http.Error(w, "Unable to render report", http.StatusInternalServerError)
	}
}

func (e *Extension) data(w http.ResponseWriter, r *http.Request) {
	source, err := e.requestedSource(r)
	if err != nil {
		reportError(w, err)
		return
	}
	data, err := e.loadData(r.Context(), source.FirewallID)
	if err != nil {
		reportError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		e.logger.Warn("report response write failed")
	}
}

func (e *Extension) download(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	// Select a complete literal query. Request values are never used to build
	// SQL identifiers, even after validation of the report kind.
	var query string
	switch kind {
	case "forwarding":
		query = "SELECT forwarding FROM report_latest WHERE firewall_id=?"
	case "technical":
		query = "SELECT technical FROM report_latest WHERE firewall_id=?"
	case "traffic":
		query = "SELECT traffic FROM report_latest WHERE firewall_id=?"
	default:
		http.NotFound(w, r)
		return
	}
	source, err := e.requestedSource(r)
	if err != nil {
		reportError(w, err)
		return
	}
	var encrypted []byte
	err = e.db.QueryRowContext(r.Context(), query, source.FirewallID).Scan(&encrypted)
	if err != nil {
		reportError(w, err)
		return
	}
	if len(encrypted) == 0 {
		reportError(w, sql.ErrNoRows)
		return
	}
	if len(encrypted) > maxReportSetBytes {
		reportError(w, errors.New("report exceeds limit"))
		return
	}
	pdf, err := e.cipher.Decrypt(encrypted)
	if err != nil {
		reportError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="FortiSafe_%d_%s.pdf"`, source.FirewallID, kind))
	w.Header().Set("Content-Length", strconv.Itoa(len(pdf)))
	if _, err := w.Write(pdf); err != nil {
		e.logger.Warn("report download write failed")
	}
	if e.logActivity != nil {
		user := ""
		if e.currentUser != nil {
			user = e.currentUser(r)
		}
		e.logActivity(user, "reports.downloaded", fmt.Sprintf("firewall_id=%d type=%s", source.FirewallID, kind))
	}
}

func (e *Extension) regenerate(w http.ResponseWriter, r *http.Request) {
	source, err := e.requestedSource(r)
	if err != nil {
		reportError(w, err)
		return
	}
	if err := e.refresh(r.Context()); err != nil {
		reportError(w, err)
		return
	}
	if err := forceRetry(r.Context(), e.db, source.FirewallID); err != nil {
		reportError(w, err)
		return
	}
	e.signal()
	if e.logActivity != nil {
		user := ""
		if e.currentUser != nil {
			user = e.currentUser(r)
		}
		e.logActivity(user, "reports.regenerate", fmt.Sprintf("firewall_id=%d", source.FirewallID))
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
			e.logger.Warn("report response write failed")
		}
		return
	}
	http.Redirect(w, r, "/reports/", http.StatusSeeOther)
}
