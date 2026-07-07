package web

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/database"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// ---- page data structs (each embeds Base for the shared layout) ----

type loginData struct {
	Error         string
	TOTPEnabled   bool
	RadiusEnabled bool
}

// loginView builds the login page data, carrying the TOTP/RADIUS flags the
// template needs to decide whether to reveal the TOTP field and show the
// "approve on your mobile" RADIUS banner.
func (s *Server) loginView(errMsg string) loginData {
	return loginData{
		Error:         errMsg,
		TOTPEnabled:   s.cfg.TOTPEnabled,
		RadiusEnabled: s.cfg.RadiusEnabled,
	}
}

type indexData struct {
	Base      BaseData
	Error     string
	Firewalls []models.Firewall
	NextRuns  map[int]time.Time
}

type backupsData struct {
	Base    BaseData
	FwID    int
	Backups []models.Backup
	Error   string
}

type errorsData struct {
	Base   BaseData
	Errors []models.Firewall
	Error  string
}

type activityLogData struct {
	Base       BaseData
	Logs       []models.ActivityLog
	Error      string
	Page       int
	TotalPages int
}

type changePasswordData struct {
	Base  BaseData
	Error string
}

type searchResult struct {
	FQDN     string
	Filename string
	Line     string
}

type searchData struct {
	Base    BaseData
	Query   string
	Results []searchResult
	Error   string
}

// handleLogin renders and processes the login form (public route).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.render(w, "login.html", s.loginView(""))
		return
	}

	ctx := r.Context()
	username := r.FormValue("username")
	password := r.FormValue("password")
	totpCode := r.FormValue("totp_code")

	// Brute-force guard keyed by client IP + username.
	rlKey := clientIP(r, s.cfg.TrustProxyHeaders) + "|" + username
	if !s.limiter.allowed(rlKey) {
		s.store.LogActivity(username, "Login Blocked", "Too many failed attempts")
		s.render(w, "login.html", s.loginView("Too many failed attempts. Please try again later."))
		return
	}

	user, localOK, err := s.store.AuthenticateLocal(ctx, username, password)
	if err != nil {
		s.logger.Error("login user lookup failed", "user", username, "err", err)
	}

	authenticated := localOK
	isRadius := false
	if !authenticated && s.auth.VerifyRadius(username, password) {
		authenticated = true
		isRadius = true
		if err := s.store.UpsertRadiusUser(ctx, username); err != nil {
			s.logger.Error("failed to upsert radius user", "user", username, "err", err)
		}
		if u, uerr := s.store.GetUserForLogin(ctx, username); uerr == nil {
			user = u
		}
	}

	// TOTP is enforced only for local (non-RADIUS) users when enabled.
	if authenticated && s.cfg.TOTPEnabled && !isRadius {
		if user != nil && user.TOTPSecret != "" {
			if !s.auth.VerifyTOTP(user.TOTPSecret, totpCode) {
				s.limiter.fail(rlKey)
				s.store.LogActivity(username, "Login Failed", "Invalid TOTP code")
				s.render(w, "login.html", s.loginView("Invalid TOTP code"))
				return
			}
		} else {
			s.limiter.fail(rlKey)
			s.store.LogActivity(username, "Login Failed", "TOTP required but no secret found")
			s.render(w, "login.html", s.loginView("TOTP required but no secret found"))
			return
		}
	}

	if !authenticated {
		s.limiter.fail(rlKey)
		s.store.LogActivity(username, "Login Failed", "Invalid credentials")
		s.render(w, "login.html", s.loginView("Invalid credentials"))
		return
	}

	s.limiter.reset(rlKey)
	if err := s.sess.Login(w, r, username, isRadius); err != nil {
		// The session was not established, so do not report/redirect as success.
		s.logger.Error("failed to establish session", "user", username, "err", err)
		s.render(w, "login.html", s.loginView("Failed to establish session. Please try again."))
		return
	}
	s.store.LogActivity(username, "Login Success", "User logged in")

	if user != nil && user.FirstLogin == 1 && !isRadius {
		http.Redirect(w, r, "/change_password", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout clears the session and returns to the login screen.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	username := s.sess.User(r).Username
	if username == "" {
		username = "unknown"
	}
	if err := s.sess.Logout(w, r); err != nil {
		s.logger.Error("failed to clear session", "err", err)
	}
	s.store.LogActivity(username, "Logout", "User logged out")
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleIndex lists firewalls and handles adds (single form + CSV bulk upload).
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := s.sess.User(r)

	if r.Method == http.MethodPost {
		// Cap the request body to guard against oversized uploads (#38).
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.CSVMaxBytes)

		// Branch (a): CSV bulk upload.
		if file, header, ferr := r.FormFile("csv_file"); ferr == nil {
			defer func() { _ = file.Close() }()
			s.handleIndexCSV(w, r, file, header, d.Username)
			return
		}

		_ = r.ParseForm()

		// Branch (b): legacy in-page password change.
		if r.PostForm.Has("username") && r.PostForm.Has("password") &&
			r.PostForm.Has("new_password") && r.PostForm.Has("confirm_password") {
			oldPassword := r.FormValue("password")
			newPassword := r.FormValue("new_password")
			confirm := r.FormValue("confirm_password")
			if newPassword != confirm {
				http.Error(w, "New passwords do not match", http.StatusBadRequest)
				return
			}
			ok, err := s.store.ChangePassword(ctx, d.Username, oldPassword, newPassword)
			if err != nil {
				s.logger.Error("change password failed", "user", d.Username, "err", err)
			}
			if ok {
				s.store.LogActivity(d.Username, "Change Password", "Password changed successfully")
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			http.Error(w, "Old password incorrect or update failed", http.StatusBadRequest)
			return
		}

		// Branch (c): single firewall add.
		fqdn := r.FormValue("fqdn")
		username := r.FormValue("username")
		if username == "" {
			username = s.cfg.DefaultSCPUser
		}
		password := r.FormValue("password")
		if password == "" {
			password = s.cfg.DefaultSCPPassword
		}
		intervalMin, ierr := strconv.Atoi(strings.TrimSpace(r.FormValue("interval_minutes")))
		retention, rerr := strconv.Atoi(strings.TrimSpace(r.FormValue("retention_count")))
		sshRaw := "9422"
		if v, ok := r.PostForm["ssh_port"]; ok && len(v) > 0 {
			sshRaw = v[0]
		}
		sshPort, serr := strconv.Atoi(strings.TrimSpace(sshRaw))
		if ierr != nil || rerr != nil || serr != nil {
			msg := "Invalid input: "
			switch {
			case ierr != nil:
				msg += ierr.Error()
			case rerr != nil:
				msg += rerr.Error()
			default:
				msg += serr.Error()
			}
			s.render(w, "index.html", indexData{Base: s.base(r, "Firewalls", "firewalls"), Error: msg})
			return
		}

		cronExpr := strings.TrimSpace(r.FormValue("cron_expr"))
		id, err := s.store.AddFirewall(ctx, models.Firewall{
			FQDN: fqdn, Username: username, Password: password,
			IntervalMin: intervalMin, RetentionCount: retention,
			Status: "New", SSHPort: sshPort, CronExpr: cronExpr,
		})
		if err != nil {
			s.render(w, "index.html", indexData{Base: s.base(r, "Firewalls", "firewalls"), Error: "Invalid input: " + err.Error()})
			return
		}
		s.store.LogActivity(d.Username, "Create Firewall", fmt.Sprintf("Created firewall with ID %d and FQDN %s", id, fqdn))
		s.scheduleFirewall(id, intervalMin, cronExpr, 10*time.Second)
		// Post/Redirect/Get so a refresh does not re-submit the form (#31).
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	fws, err := s.store.ListFirewalls(ctx)
	if err != nil {
		s.logger.Error("failed to list firewalls", "err", err)
	}
	firstLogin, found, ferr := s.store.GetFirstLogin(ctx, d.Username)
	if ferr != nil {
		s.logger.Error("failed to get first_login", "user", d.Username, "err", ferr)
	}
	if found && firstLogin == 1 && !d.IsRadiusUser {
		http.Redirect(w, r, "/change_password", http.StatusFound)
		return
	}
	nextRuns := make(map[int]time.Time, len(fws))
	for _, fw := range fws {
		if info, ok := s.sched.Info(BackupJobID(fw.ID)); ok {
			nextRuns[fw.ID] = info.NextRun
		}
	}
	s.render(w, "index.html", indexData{
		Base:      s.base(r, "Firewalls", "firewalls"),
		Firewalls: fws,
		NextRuns:  nextRuns,
	})
}

// handleIndexCSV processes a bulk CSV upload from the index form.
func (s *Server) handleIndexCSV(w http.ResponseWriter, r *http.Request, file multipart.File, header *multipart.FileHeader, actor string) {
	ctx := r.Context()
	renderErr := func(msg string, fws []models.Firewall) {
		s.render(w, "index.html", indexData{Base: s.base(r, "Firewalls", "firewalls"), Error: msg, Firewalls: fws})
	}

	if header.Filename == "" {
		renderErr("No file selected", nil)
		return
	}
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".csv") {
		renderErr("File must be a CSV", nil)
		return
	}

	cr := csv.NewReader(file)
	cr.FieldsPerRecord = -1
	records, err := cr.ReadAll()
	if err != nil {
		renderErr("Failed to process CSV: "+err.Error(), nil)
		return
	}
	if len(records) == 0 {
		renderErr("CSV must contain fqdn, interval_minutes, retention_count headers", nil)
		return
	}

	colIdx := make(map[string]int)
	for i, h := range records[0] {
		colIdx[strings.TrimSpace(h)] = i
	}
	for _, req := range []string{"fqdn", "interval_minutes", "retention_count"} {
		if _, ok := colIdx[req]; !ok {
			renderErr("CSV must contain fqdn, interval_minutes, retention_count headers", nil)
			return
		}
	}

	get := func(row []string, name string) (string, bool) {
		idx, ok := colIdx[name]
		if !ok || idx >= len(row) {
			return "", false
		}
		return row[idx], true
	}

	var rowErrors []string
	added := 0
	for _, row := range records[1:] {
		fqdnRaw, _ := get(row, "fqdn")
		fqdn := strings.TrimSpace(fqdnRaw)

		username := s.cfg.DefaultSCPUser
		if v, ok := get(row, "username"); ok && strings.TrimSpace(v) != "" {
			username = strings.TrimSpace(v)
		}
		password := s.cfg.DefaultSCPPassword
		if v, ok := get(row, "password"); ok && strings.TrimSpace(v) != "" {
			password = strings.TrimSpace(v)
		}

		intervalRaw, _ := get(row, "interval_minutes")
		intervalMin, ierr := strconv.Atoi(strings.TrimSpace(intervalRaw))
		if ierr != nil {
			rowErrors = append(rowErrors, fmt.Sprintf("Invalid data in row %v: %s", row, ierr.Error()))
			continue
		}
		retentionRaw, _ := get(row, "retention_count")
		retention, rerr := strconv.Atoi(strings.TrimSpace(retentionRaw))
		if rerr != nil {
			rowErrors = append(rowErrors, fmt.Sprintf("Invalid data in row %v: %s", row, rerr.Error()))
			continue
		}
		sshRaw := "9422"
		if v, ok := get(row, "ssh_port"); ok && strings.TrimSpace(v) != "" {
			sshRaw = strings.TrimSpace(v)
		}
		sshPort, serr := strconv.Atoi(sshRaw)
		if serr != nil {
			rowErrors = append(rowErrors, fmt.Sprintf("Invalid data in row %v: %s", row, serr.Error()))
			continue
		}

		if fqdn == "" {
			rowErrors = append(rowErrors, fmt.Sprintf("Missing FQDN in row: %v", row))
			continue
		}

		id, aerr := s.store.AddFirewall(ctx, models.Firewall{
			FQDN: fqdn, Username: username, Password: password,
			IntervalMin: intervalMin, RetentionCount: retention,
			Status: "New", SSHPort: sshPort,
		})
		if aerr != nil {
			rowErrors = append(rowErrors, fmt.Sprintf("Invalid data in row %v: %s", row, aerr.Error()))
			continue
		}
		added++
		s.store.LogActivity(actor, "Create Firewall", fmt.Sprintf("Created firewall with ID %d and FQDN %s via bulk upload", id, fqdn))
		s.scheduleFirewall(id, intervalMin, "", time.Duration(added*10)*time.Second)
	}

	if len(rowErrors) > 0 {
		fws, _ := s.store.ListFirewalls(ctx)
		renderErr("Some firewalls were not added due to errors: "+strings.Join(rowErrors, "; "), fws)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// scheduleFirewall registers a backup job, preferring a cron expression over
// the interval. No-op if a job already exists.
func (s *Server) scheduleFirewall(fwID, intervalMin int, cronExpr string, firstDelay time.Duration) {
	jobID := BackupJobID(fwID)
	if s.sched.Has(jobID) {
		return
	}
	if cronExpr != "" {
		if err := s.sched.ScheduleCron(jobID, cronExpr, func() { s.backup.Backup(fwID) }); err == nil {
			return
		} else {
			s.logger.Warn("invalid cron, using interval", "fw_id", fwID, "cron", cronExpr, "err", err)
		}
	}
	if intervalMin <= 0 {
		intervalMin = 180
	}
	s.sched.Schedule(jobID, time.Duration(intervalMin)*time.Minute, firstDelay, func() { s.backup.Backup(fwID) })
}

// handleListBackups shows the stored configurations for one firewall.
func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	base := s.base(r, "Backups", "firewalls")
	backups, err := s.store.ListBackups(r.Context(), fwID)
	if err != nil {
		s.logger.Error("failed to retrieve backups", "fw", fwID, "err", err)
		s.render(w, "backups.html", backupsData{Base: base, FwID: fwID, Error: "Failed to load backups"})
		return
	}
	s.render(w, "backups.html", backupsData{Base: base, FwID: fwID, Backups: backups})
}

// handleDownload serves a stored configuration file, decrypting it on the fly
// when encryption at rest is enabled so the user always downloads plaintext.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "*")
	if filename == "" || strings.Contains(filename, "..") {
		http.NotFound(w, r)
		return
	}
	diskPath := filepath.Join(s.cfg.BackupDir, filepath.FromSlash(filename))
	raw, err := os.ReadFile(diskPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	plain, err := s.cipher.Decrypt(raw)
	if err != nil {
		s.logger.Error("failed to decrypt backup for download", "file", filename, "err", err)
		http.Error(w, "failed to read backup", http.StatusInternalServerError)
		return
	}
	s.store.LogActivity(s.sess.User(r).Username, "Download Config", "Downloaded configuration file: "+filename)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(filename)+"\"")
	http.ServeContent(w, r, filepath.Base(filename), time.Time{}, bytes.NewReader(plain))
}

// handleDeleteFirewall removes a firewall, its backups, its files and its job.
func (s *Server) handleDeleteFirewall(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	actor := s.sess.User(r).Username
	fqdn, err := s.store.DeleteFirewall(r.Context(), fwID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			s.store.LogActivity(actor, "Delete Firewall Failed", fmt.Sprintf("Firewall not found: fw_id %d", fwID))
		} else {
			s.logger.Error("failed to delete firewall", "fw", fwID, "err", err)
			s.store.LogActivity(actor, "Delete Firewall Failed", fmt.Sprintf("Failed to delete firewall fw_id %d: %s", fwID, err.Error()))
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if rerr := os.RemoveAll(filepath.Join(s.cfg.BackupDir, strconv.Itoa(fwID))); rerr != nil {
		s.logger.Error("failed to remove backup directory", "fw", fwID, "err", rerr)
	}
	s.sched.Remove(BackupJobID(fwID))
	s.store.LogActivity(actor, "Delete Firewall", fmt.Sprintf("Deleted firewall %s with ID %d", fqdn, fwID))
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleErrors lists firewalls whose last backup failed.
func (s *Server) handleErrors(w http.ResponseWriter, r *http.Request) {
	base := s.base(r, "Errors", "firewalls")
	errs, err := s.store.ListErrors(r.Context())
	if err != nil {
		s.logger.Error("failed to retrieve errors", "err", err)
		s.render(w, "errors.html", errorsData{Base: base, Error: "Failed to load errors"})
		return
	}
	s.render(w, "errors.html", errorsData{Base: base, Errors: errs})
}

// handleBackupNow triggers an asynchronous backup then returns to the index so
// the request does not block on the SSH/SCP timeout.
func (s *Server) handleBackupNow(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.store.LogActivity(s.sess.User(r).Username, "Backup Now", fmt.Sprintf("Manual backup triggered for fw_id %d", fwID))
	s.backup.Enqueue(fwID)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleChangePassword renders and processes the password change form.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := s.sess.User(r)
	base := s.base(r, "Change Password", "password")

	if d.IsRadiusUser {
		s.store.LogActivity(d.Username, "Password Change Attempt", "Password change denied for RADIUS user")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.Method != http.MethodPost {
		s.render(w, "change_password.html", changePasswordData{Base: base})
		return
	}

	oldPassword := r.FormValue("old_password")
	newPassword := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")
	if newPassword != confirm {
		s.render(w, "change_password.html", changePasswordData{Base: base, Error: "New passwords do not match"})
		return
	}
	ok, err := s.store.ChangePassword(ctx, d.Username, oldPassword, newPassword)
	if err != nil {
		s.logger.Error("failed to change password", "user", d.Username, "err", err)
		s.render(w, "change_password.html", changePasswordData{Base: base, Error: "Failed to change password"})
		return
	}
	if ok {
		s.store.LogActivity(d.Username, "Change Password", "Password changed successfully")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.render(w, "change_password.html", changePasswordData{Base: base, Error: "Old password incorrect"})
}

// handleSearch searches the newest configuration of every firewall.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := searchData{Base: s.base(r, "Search", "search")}

	if r.Method == http.MethodPost {
		query := r.FormValue("query")
		data.Query = query
		if query != "" {
			s.store.LogActivity(s.sess.User(r).Username, "Search", "Performed search for: "+query)

			pattern, err := buildSearchPattern(query)
			if err != nil {
				data.Error = "Invalid search pattern: " + err.Error()
				s.render(w, "search.html", data)
				return
			}

			refs, err := s.store.ListFirewallRefs(ctx)
			if err != nil {
				data.Error = "An error occurred during search: " + err.Error()
				s.render(w, "search.html", data)
				return
			}
			for _, ref := range refs {
				results := s.searchFirewall(ref, pattern)
				data.Results = append(data.Results, results...)
			}
		}
	}
	s.render(w, "search.html", data)
}

// buildSearchPattern converts a user query into a case-insensitive regexp where
// '*' is a wildcard and everything else is treated literally. Invalid UTF-8 in
// the query is sanitized so the pattern always compiles.
func buildSearchPattern(query string) (*regexp.Regexp, error) {
	parts := strings.Split(query, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(strings.ToValidUTF8(p, ""))
	}
	return regexp.Compile("(?i)" + strings.Join(parts, ".*"))
}

// searchFirewall scans the newest .conf file of one firewall for pattern matches.
func (s *Server) searchFirewall(ref models.FirewallRef, pattern *regexp.Regexp) []searchResult {
	fwDir := filepath.Join(s.cfg.BackupDir, strconv.Itoa(ref.ID))
	entries, err := os.ReadDir(fwDir)
	if err != nil {
		return nil
	}

	var latest string
	var latestMod time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		if latest == "" || info.ModTime().After(latestMod) {
			latest = e.Name()
			latestMod = info.ModTime()
		}
	}
	if latest == "" {
		return nil
	}

	fpath := filepath.Join(fwDir, latest)
	raw, err := os.ReadFile(fpath)
	if err != nil {
		s.logger.Error("error reading file", "path", fpath, "err", err)
		return nil
	}
	plain, err := s.cipher.Decrypt(raw)
	if err != nil {
		s.logger.Error("error decrypting file", "path", fpath, "err", err)
		return nil
	}

	relName := filepath.ToSlash(filepath.Join(strconv.Itoa(ref.ID), latest))
	var results []searchResult
	sc := bufio.NewScanner(bytes.NewReader(plain))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if pattern.MatchString(line) {
			results = append(results, searchResult{
				FQDN:     ref.FQDN,
				Filename: relName,
				Line:     strings.TrimSpace(line),
			})
		}
	}
	return results
}

const activityPageSize = 100

// handleActivityLog renders a page of activity, newest first.
func (s *Server) handleActivityLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	base := s.base(r, "Activity Log", "activity")

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	total, err := s.store.CountActivityLogs(ctx)
	if err != nil {
		s.logger.Error("failed to count activity logs", "err", err)
	}
	totalPages := (total + activityPageSize - 1) / activityPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	logs, err := s.store.ListActivityLogs(ctx, activityPageSize, (page-1)*activityPageSize)
	if err != nil {
		s.logger.Error("failed to retrieve activity logs", "err", err)
		s.render(w, "activity_log.html", activityLogData{Base: base, Error: "Failed to load activity logs", Page: 1, TotalPages: 1})
		return
	}
	s.render(w, "activity_log.html", activityLogData{Base: base, Logs: logs, Page: page, TotalPages: totalPages})
}
