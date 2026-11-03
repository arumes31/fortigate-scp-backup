package fgt_reports

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

type profileDocument struct {
	Format  string              `json:"format"`
	Profile reportmodel.Profile `json:"profile"`
}

const profileFormat = "fortisafe-report-profile/v2"

func (e *Extension) profile(w http.ResponseWriter, r *http.Request) {
	source, err := e.requestedSource(r)
	if err != nil {
		reportError(w, err)
		return
	}
	saved, err := e.getProfile(r.Context(), source.FirewallID)
	if err != nil {
		reportError(w, err)
		return
	}
	view, err := e.profileView(r, source, saved)
	if err != nil {
		reportError(w, err)
		return
	}
	if r.URL.Query().Get("notice") == "saved" {
		view.Notice = reportText(view.Base.Lang, "profile_saved")
	}
	e.renderProfileView(w, view, http.StatusOK)
}

func (e *Extension) profileView(r *http.Request, source reportmodel.Source, saved savedProfile) (profilePageData, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	sources, err := e.listSources(ctx)
	if err != nil {
		return profilePageData{}, err
	}
	data, _ := e.loadData(ctx, source.FirewallID)
	return buildProfileView(e.pageBase(r, "Report profile", "reports"), source, saved.Profile, data.Assessment, sources, displayTime(saved.NextDue)), nil
}

func (e *Extension) renderProfileView(w http.ResponseWriter, view profilePageData, status int) {
	var output bytes.Buffer
	if err := e.profilePage.Render(&output, view); err != nil {
		e.logger.Error("report profile page rendering failed")
		http.Error(w, "Unable to render report profile", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if _, err := output.WriteTo(w); err != nil {
		e.logger.Warn("report profile response write failed")
	}
}

func parseReportForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxProfileBytes+(64<<10))
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		return r.ParseMultipartForm(maxProfileBytes + (64 << 10))
	}
	return r.ParseForm()
}

func cleanupReportForm(r *http.Request) {
	if r.MultipartForm != nil {
		_ = r.MultipartForm.RemoveAll()
	}
}

func uploadedProfilePart(r *http.Request, name string, limit int64) ([]byte, bool, error) {
	file, _, err := r.FormFile(name)
	if errors.Is(err, http.ErrMissingFile) || errors.Is(err, http.ErrNotMultipart) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(data)) > limit {
		return nil, true, errors.New("uploaded report file exceeds limit")
	}
	return data, true, nil
}

func profileFromForm(r *http.Request, prior reportmodel.Profile) (reportmodel.Profile, error) {
	p := prior
	p.Name, p.Organization, p.Customer = r.FormValue("name"), r.FormValue("organization"), r.FormValue("customer")
	p.Subtitle, p.Intro, p.Footer = r.FormValue("subtitle"), r.FormValue("intro"), r.FormValue("footer")
	p.Accent, p.Language, p.Orientation = r.FormValue("accent"), r.FormValue("language"), r.FormValue("orientation")
	p.Cover, p.Contents = r.FormValue("cover") != "", r.FormValue("contents") != ""
	p.ShowFindings, p.ShowInventory, p.ShowTraces = r.FormValue("show_findings") != "", r.FormValue("show_inventory") != "", r.FormValue("show_traces") != ""
	p.Sections, p.Charts = r.Form["sections"], r.Form["charts"]
	p.Filters = reportmodel.Filters{VDOMs: r.Form["vdoms"], Types: r.Form["types"], Outcomes: r.Form["outcomes"], Priorities: r.Form["priorities"]}
	p.Traffic, p.TimeRange = r.FormValue("traffic") != "", r.FormValue("time_range")
	p.Schedule.Frequency, p.Schedule.Timezone = r.FormValue("frequency"), r.FormValue("timezone")
	for _, field := range []struct {
		name string
		into *int
	}{{"hour", &p.Schedule.Hour}, {"minute", &p.Schedule.Minute}, {"weekday", &p.Schedule.Weekday}, {"month_day", &p.Schedule.MonthDay}} {
		value, err := strconv.Atoi(r.FormValue(field.name))
		if err != nil {
			return p, errors.New("report schedule fields must be integers")
		}
		*field.into = value
	}
	if r.FormValue("remove_logo") != "" {
		p.LogoBase64 = ""
	}
	data, present, err := uploadedProfilePart(r, "logo", 256<<10)
	if err != nil {
		return p, err
	}
	if present && len(data) > 0 {
		p.LogoBase64 = base64.StdEncoding.EncodeToString(data)
	}
	normalized, err := reportmodel.NormalizeProfile(p)
	if err != nil {
		return p, err
	}
	return normalized, nil
}

func (e *Extension) updateProfile(w http.ResponseWriter, r *http.Request) {
	e.mutateProfile(w, r, "save")
}

func (e *Extension) importProfile(w http.ResponseWriter, r *http.Request) {
	e.mutateProfile(w, r, "import")
}

func (e *Extension) resetProfile(w http.ResponseWriter, r *http.Request) {
	e.mutateProfile(w, r, "reset")
}

func (e *Extension) copyProfile(w http.ResponseWriter, r *http.Request) {
	e.mutateProfile(w, r, "copy")
}

func (e *Extension) mutateProfile(w http.ResponseWriter, r *http.Request, operation string) {
	source, err := e.requestedSource(r)
	if err != nil {
		reportError(w, err)
		return
	}
	if err := parseReportForm(w, r); err != nil {
		http.Error(w, "Report profile form is invalid or too large", http.StatusBadRequest)
		return
	}
	defer cleanupReportForm(r)
	saved, err := e.getProfile(r.Context(), source.FirewallID)
	if err != nil {
		reportError(w, err)
		return
	}
	p := saved.Profile
	switch operation {
	case "save":
		p, err = profileFromForm(r, p)
	case "reset":
		p = reportmodel.DefaultProfile(e.cfg.ReportsLanguage)
	case "import":
		var data []byte
		var present bool
		data, present, err = uploadedProfilePart(r, "profile_file", maxProfileBytes)
		if err == nil && !present {
			err = errors.New("select a FortiSafe report profile document")
		}
		if err == nil {
			var document profileDocument
			err = decodeProfileJSON(data, &document)
			if err == nil && document.Format != profileFormat {
				err = errors.New("unsupported report profile format")
			}
			if err == nil {
				p, err = reportmodel.NormalizeProfile(document.Profile)
			}
		}
	case "copy":
		p, err = e.copyProfileDefinition(r)
	default:
		http.NotFound(w, r)
		return
	}
	if err == nil {
		err = e.saveProfile(r.Context(), source, p, r.FormValue("revision"), operation == "reset")
		if err != nil && !errors.Is(err, errProfileConflict) {
			reportError(w, err)
			return
		}
	}
	if err != nil {
		display := saved
		if operation == "save" {
			display.Profile = p
		}
		view, viewErr := e.profileView(r, source, display)
		if viewErr != nil {
			reportError(w, viewErr)
			return
		}
		view.Revision = reportmodel.ProfileHash(saved.Profile)
		view.Error = err.Error()
		status := http.StatusBadRequest
		if errors.Is(err, errProfileConflict) {
			status = http.StatusConflict
		}
		e.renderProfileView(w, view, status)
		return
	}
	if e.logActivity != nil {
		user := ""
		if e.currentUser != nil {
			user = e.currentUser(r)
		}
		e.logActivity(user, "reports.profile."+operation, fmt.Sprintf("firewall_id=%d", source.FirewallID))
	}
	http.Redirect(w, r, fmt.Sprintf("/reports/%d/profile?notice=saved", source.FirewallID), http.StatusSeeOther)
}

func (e *Extension) copyProfileDefinition(r *http.Request) (reportmodel.Profile, error) {
	id, err := strconv.Atoi(r.FormValue("source_firewall_id"))
	if err != nil || id <= 0 {
		return reportmodel.Profile{}, errors.New("select a source firewall")
	}
	sources, err := e.listSources(r.Context())
	if err != nil {
		return reportmodel.Profile{}, errors.New("report sources are temporarily unavailable")
	}
	for _, source := range sources {
		if source.FirewallID == id {
			p, err := e.getProfile(r.Context(), id)
			if err != nil {
				return reportmodel.Profile{}, errors.New("source report profile is temporarily unavailable")
			}
			return p.Profile, nil
		}
	}
	return reportmodel.Profile{}, errors.New("source firewall is no longer available")
}

func (e *Extension) exportProfile(w http.ResponseWriter, r *http.Request) {
	source, err := e.requestedSource(r)
	if err != nil {
		reportError(w, err)
		return
	}
	saved, err := e.getProfile(r.Context(), source.FirewallID)
	if err != nil {
		reportError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="FortiSafe_%d_profile.json"`, source.FirewallID))
	if err := json.NewEncoder(w).Encode(profileDocument{Format: profileFormat, Profile: saved.Profile}); err != nil {
		e.logger.Warn("report profile response write failed")
	}
}

func (e *Extension) catalog(w http.ResponseWriter, r *http.Request) {
	view := buildCatalogView(e.pageBase(r, "Report catalog", "reports"))
	view.GraylogConfigured = strings.TrimSpace(e.cfg.GraylogURL) != "" && strings.TrimSpace(e.cfg.GraylogToken) != ""
	if view.GraylogConfigured {
		for i := range view.Families {
			if view.Families[i].Availability == "requires_graylog" {
				view.Families[i].Availability = "graylog"
			}
		}
		for i := range view.Datasets {
			if view.Datasets[i].Availability == "requires_graylog" {
				view.Datasets[i].Availability = "graylog"
			}
		}
	}
	if err := e.catalogPage.RenderHTTP(w, view); err != nil {
		e.logger.Error("report catalog rendering failed")
		http.Error(w, "Unable to render report catalog", http.StatusInternalServerError)
	}
}

func (e *Extension) calendar(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	sources, err := e.listSources(ctx)
	if err != nil {
		reportError(w, err)
		return
	}
	view := calendarPageData{Base: e.pageBase(r, "Report schedule", "reports")}
	for _, source := range sources {
		saved, err := e.getProfile(ctx, source.FirewallID)
		if err != nil {
			reportError(w, err)
			return
		}
		view.Rows = append(view.Rows, reportScheduleRow{FirewallID: source.FirewallID, Firewall: source.Firewall,
			Profile: saved.Profile.Name, Frequency: saved.Profile.Schedule.Frequency, Timezone: saved.Profile.Schedule.Timezone, NextDue: displayTime(saved.NextDue)})
	}
	sort.SliceStable(view.Rows, func(i, j int) bool { return view.Rows[i].NextDue < view.Rows[j].NextDue })
	if err := e.calendarPage.RenderHTTP(w, view); err != nil {
		e.logger.Error("report schedule rendering failed")
		http.Error(w, "Unable to render report schedule", http.StatusInternalServerError)
	}
}
