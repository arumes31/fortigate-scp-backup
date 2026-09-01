package fgtconftail

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	dashboardStateAll      = "all"
	dashboardPageSize      = 25
	dashboardActiveLimit   = 100
	dashboardEventPageSize = 100
	dashboardVDOMLimit     = 20
	dashboardMaxPage       = 10_000
	dashboardWhereSQL      = `c.state = ?
		AND (? = 0 OR c.firewall_id = ?)
		AND (? = 0 OR LOWER(c.user) LIKE LOWER(?) ESCAPE '\')
		AND (? = 0 OR c.last_event_at_ns >= ?)
		AND (? = 0 OR c.first_event_at_ns <= ?)
		AND (? = 0 OR o.state = ?)`
	dashboardChainSelectSQL = `SELECT
		c.id, c.firewall_id, c.firewall_name, c.user, c.first_event_at_ns,
		c.last_event_at_ns, c.event_count, c.state, c.late, c.unattributed,
		c.sealed_at_ns, COALESCE(o.state, ''), COALESCE(o.attempt_count, 0),
		COALESCE(o.next_attempt_at_ns, 0), COALESCE(o.last_error, ''),
		COALESCE(o.request_id, ''), COALESCE(o.accepted_at_ns, 0)
		FROM chains c LEFT JOIN outbox o ON o.chain_id = c.id`
)

//go:embed templates/*.html static/*.css
var dashboardFS embed.FS

type dashboardFilters struct {
	FirewallID int
	User       string
	State      string
	From       time.Time
	To         time.Time
	Page       int
}

type dashboardCounts struct {
	Active   int
	Sealed   int
	Pending  int
	Retry    int
	Failed   int
	Accepted int
}

type dashboardEvent struct {
	EventAt         time.Time
	Source          string
	DeviceName      string
	DeviceID        string
	VDOM            string
	UserAttribution string
	UI              string
	Action          string
	TransactionID   string
	Path            string
	Object          string
	ConfigAttribute string
	LogID           string
	LogDescription  string
	Message         string
	Late            bool
}

type dashboardChain struct {
	ID               string
	FirewallID       int
	FirewallName     string
	User             string
	FirstEventAt     time.Time
	LastEventAt      time.Time
	EventCount       int
	State            string
	Late             bool
	Unattributed     bool
	SealedAt         time.Time
	DeliveryState    string
	DeliveryAttempts int
	NextAttemptAt    time.Time
	LastError        string
	RequestID        string
	AcceptedAt       time.Time
	Events           []dashboardEvent
	VDOMs            []string
	VDOMsOmitted     int
	QuietEligibleAt  time.Time
}

type dashboardData struct {
	Poll         PollState
	Counts       dashboardCounts
	Active       []dashboardChain
	ActiveTotal  int
	History      []dashboardChain
	HistoryTotal int
	TotalPages   int
}

type dashboardFilterView struct {
	Firewall string
	User     string
	State    string
	From     string
	To       string
	Page     int
}

type dashboardHealth struct {
	State  string
	Label  string
	Detail string
}

type conftailBaseData struct {
	Username            string
	ExtAdmVPNEnabled    bool
	ExtConfigGenEnabled bool
	ExtPolSplitEnabled  bool
	ExtConfConvEnabled  bool
}

type dashboardPageData struct {
	Base          conftailBaseData
	Dashboard     dashboardData
	Filters       dashboardFilterView
	Health        dashboardHealth
	NextPollRun   time.Time
	Coverage      []sourceCoverage
	Warnings      []string
	ActiveOmitted int
	PrevURL       string
	NextURL       string
}

type dashboardChainPageData struct {
	Base       conftailBaseData
	Chain      dashboardChain
	Page       int
	TotalPages int
	PrevURL    string
	NextURL    string
}

func parseDashboardTemplate() (*template.Template, error) {
	return template.New("index.html").Funcs(template.FuncMap{
		"fmtTime":     formatDashboardTime,
		"fmtDuration": formatDashboardDuration,
	}).ParseFS(dashboardFS, "templates/*.html")
}

func dashboardStaticFS() (fs.FS, error) {
	return fs.Sub(dashboardFS, "static")
}

func parseDashboardFilters(values url.Values) (dashboardFilters, error) {
	filters := dashboardFilters{
		User:  strings.TrimSpace(values.Get("user")),
		State: strings.TrimSpace(values.Get("state")),
		Page:  1,
	}
	if filters.State == "" {
		filters.State = dashboardStateAll
	}
	if utf8.RuneCountInString(filters.User) > maxIdentityRunes {
		return dashboardFilters{}, errors.New("dashboard user filter is too long")
	}
	if !validDashboardState(filters.State) {
		return dashboardFilters{}, errors.New("invalid dashboard state filter")
	}

	if value := strings.TrimSpace(values.Get("firewall")); value != "" {
		firewallID, err := strconv.ParseInt(value, 10, 32)
		if err != nil || firewallID <= 0 {
			return dashboardFilters{}, errors.New("invalid dashboard firewall filter")
		}
		filters.FirewallID = int(firewallID)
	}
	if value := strings.TrimSpace(values.Get("page")); value != "" {
		page, err := strconv.Atoi(value)
		if err != nil || page < 1 || page > dashboardMaxPage {
			return dashboardFilters{}, errors.New("invalid dashboard page")
		}
		filters.Page = page
	}

	var err error
	if filters.From, err = parseDashboardTime(values.Get("from")); err != nil {
		return dashboardFilters{}, fmt.Errorf("invalid dashboard start time: %w", err)
	}
	if filters.To, err = parseDashboardTime(values.Get("to")); err != nil {
		return dashboardFilters{}, fmt.Errorf("invalid dashboard end time: %w", err)
	}
	if !filters.From.IsZero() && !filters.To.IsZero() && filters.From.After(filters.To) {
		return dashboardFilters{}, errors.New("dashboard start time is after end time")
	}
	return filters, nil
}

func parseDashboardTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	if len(value) > 64 {
		return time.Time{}, errors.New("timestamp is too long")
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04Z07:00",
		"2006-01-02T15:04",
	} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, errors.New("timestamp must be RFC3339 or YYYY-MM-DDTHH:MM")
}

func validDashboardState(state string) bool {
	switch state {
	case dashboardStateAll, chainStateActive, chainStateSealed,
		deliveryStatePending, deliveryStateRetry, deliveryStateFailed, deliveryStateAccepted:
		return true
	default:
		return false
	}
}

func (s *store) queryDashboard(
	ctx context.Context,
	filters dashboardFilters,
) (dashboardData, error) {
	if s == nil || s.db == nil {
		return dashboardData{}, errors.New("conftail dashboard store is unavailable")
	}
	if filters.State == "" {
		filters.State = dashboardStateAll
	}
	if !validDashboardState(filters.State) || filters.Page < 1 || filters.Page > dashboardMaxPage {
		return dashboardData{}, errors.New("invalid conftail dashboard filters")
	}

	poll, err := s.pollState(ctx)
	if err != nil {
		return dashboardData{}, err
	}
	counts, err := s.dashboardCounts(ctx)
	if err != nil {
		return dashboardData{}, err
	}
	result := dashboardData{Poll: poll, Counts: counts, TotalPages: 1}

	if filters.State == dashboardStateAll || filters.State == chainStateActive {
		args := dashboardQueryArgs(filters, chainStateActive)
		result.ActiveTotal, err = s.countDashboardChains(ctx, args)
		if err != nil {
			return dashboardData{}, err
		}
		result.Active, err = s.dashboardChains(
			ctx,
			args,
			dashboardActiveLimit,
			0,
		)
		if err != nil {
			return dashboardData{}, err
		}
	}

	if filters.State != chainStateActive {
		args := dashboardQueryArgs(filters, chainStateSealed)
		result.HistoryTotal, err = s.countDashboardChains(ctx, args)
		if err != nil {
			return dashboardData{}, err
		}
		result.TotalPages = max(1, (result.HistoryTotal+dashboardPageSize-1)/dashboardPageSize)
		result.History, err = s.dashboardChains(
			ctx,
			args,
			dashboardPageSize,
			(filters.Page-1)*dashboardPageSize,
		)
		if err != nil {
			return dashboardData{}, err
		}
	}
	return result, nil
}

func (s *store) dashboardCounts(ctx context.Context) (dashboardCounts, error) {
	var counts dashboardCounts
	err := s.db.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(CASE WHEN c.state = 'active' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN c.state = 'sealed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN o.state = 'pending' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN o.state = 'retry' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN o.state = 'failed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN o.state = 'accepted' THEN 1 ELSE 0 END), 0)
		FROM chains c LEFT JOIN outbox o ON o.chain_id = c.id`).Scan(
		&counts.Active,
		&counts.Sealed,
		&counts.Pending,
		&counts.Retry,
		&counts.Failed,
		&counts.Accepted,
	)
	if err != nil {
		return dashboardCounts{}, fmt.Errorf("read conftail dashboard counts: %w", err)
	}
	return counts, nil
}

func dashboardQueryArgs(filters dashboardFilters, chainState string) []any {
	deliveryState := ""
	if chainState == chainStateSealed && isDashboardDeliveryState(filters.State) {
		deliveryState = filters.State
	}
	return []any{
		chainState,
		boolInt(filters.FirewallID > 0), filters.FirewallID,
		boolInt(filters.User != ""), "%" + escapeDashboardLike(filters.User) + "%",
		boolInt(!filters.From.IsZero()), unixNanos(filters.From),
		boolInt(!filters.To.IsZero()), unixNanos(filters.To),
		boolInt(deliveryState != ""), deliveryState,
	}
}

func isDashboardDeliveryState(state string) bool {
	switch state {
	case deliveryStatePending, deliveryStateRetry, deliveryStateFailed, deliveryStateAccepted:
		return true
	default:
		return false
	}
}

func escapeDashboardLike(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(value)
}

func (s *store) countDashboardChains(
	ctx context.Context,
	args []any,
) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM chains c
		LEFT JOIN outbox o ON o.chain_id = c.id WHERE ` + dashboardWhereSQL
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count conftail dashboard chains: %w", err)
	}
	return count, nil
}

func (s *store) dashboardChains(
	ctx context.Context,
	args []any,
	limit int,
	offset int,
) ([]dashboardChain, error) {
	query := dashboardChainSelectSQL + ` WHERE ` + dashboardWhereSQL + `
		ORDER BY c.last_event_at_ns DESC, c.id LIMIT ? OFFSET ?`
	queryArgs := append(append([]any{}, args...), limit, offset)
	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("list conftail dashboard chains: %w", err)
	}
	defer func() { _ = rows.Close() }()

	chains := make([]dashboardChain, 0)
	for rows.Next() {
		chain, scanErr := scanDashboardChain(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan conftail dashboard chain: %w", scanErr)
		}
		chains = append(chains, chain)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate conftail dashboard chains: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close conftail dashboard chains: %w", err)
	}

	for index := range chains {
		chains[index].VDOMs, chains[index].VDOMsOmitted, err = s.dashboardVDOMs(ctx, chains[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return chains, nil
}

type dashboardScanner interface {
	Scan(dest ...any) error
}

func scanDashboardChain(scanner dashboardScanner) (dashboardChain, error) {
	var chain dashboardChain
	var first, last, sealed, nextAttempt, accepted int64
	var late, unattributed int
	if err := scanner.Scan(
		&chain.ID,
		&chain.FirewallID,
		&chain.FirewallName,
		&chain.User,
		&first,
		&last,
		&chain.EventCount,
		&chain.State,
		&late,
		&unattributed,
		&sealed,
		&chain.DeliveryState,
		&chain.DeliveryAttempts,
		&nextAttempt,
		&chain.LastError,
		&chain.RequestID,
		&accepted,
	); err != nil {
		return dashboardChain{}, err
	}
	chain.FirstEventAt = timeFromNanos(first)
	chain.LastEventAt = timeFromNanos(last)
	chain.SealedAt = timeFromNanos(sealed)
	chain.NextAttemptAt = timeFromNanos(nextAttempt)
	chain.AcceptedAt = timeFromNanos(accepted)
	chain.Late = late != 0
	chain.Unattributed = unattributed != 0
	return chain, nil
}

func scanDashboardEvent(scanner dashboardScanner) (dashboardEvent, error) {
	var event dashboardEvent
	var eventAt int64
	var late int
	if err := scanner.Scan(
		&eventAt,
		&event.Source,
		&event.DeviceName,
		&event.DeviceID,
		&event.VDOM,
		&event.UserAttribution,
		&event.UI,
		&event.Action,
		&event.TransactionID,
		&event.Path,
		&event.Object,
		&event.ConfigAttribute,
		&event.LogID,
		&event.LogDescription,
		&event.Message,
		&late,
	); err != nil {
		return dashboardEvent{}, err
	}
	event.EventAt = timeFromNanos(eventAt)
	event.Late = late != 0
	return event, nil
}

func (s *store) dashboardVDOMs(ctx context.Context, chainID string) ([]string, int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT vdom FROM events
		WHERE chain_id = ? AND vdom != '' GROUP BY vdom ORDER BY vdom LIMIT ?`,
		chainID, dashboardVDOMLimit+1)
	if err != nil {
		return nil, 0, fmt.Errorf("list conftail dashboard VDOMs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	vdoms := make([]string, 0, dashboardVDOMLimit)
	for rows.Next() {
		var vdom string
		if err := rows.Scan(&vdom); err != nil {
			return nil, 0, fmt.Errorf("scan conftail dashboard VDOM: %w", err)
		}
		vdoms = append(vdoms, vdom)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate conftail dashboard VDOMs: %w", err)
	}
	omitted := 0
	if len(vdoms) > dashboardVDOMLimit {
		vdoms = vdoms[:dashboardVDOMLimit]
		omitted = 1
	}
	return vdoms, omitted, nil
}

var (
	errDashboardChainNotFound = errors.New("conftail dashboard chain not found")
	errDashboardPageRange     = errors.New("conftail dashboard page is out of range")
)

func (s *store) dashboardChainPage(
	ctx context.Context,
	chainID string,
	page int,
) (dashboardChain, int, error) {
	if page < 1 || page > dashboardMaxPage {
		return dashboardChain{}, 0, errDashboardPageRange
	}
	chain, err := scanDashboardChain(s.db.QueryRowContext(
		ctx,
		dashboardChainSelectSQL+` WHERE c.id = ?`,
		chainID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return dashboardChain{}, 0, errDashboardChainNotFound
	}
	if err != nil {
		return dashboardChain{}, 0, fmt.Errorf("read conftail dashboard chain: %w", err)
	}
	var eventCount int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM events WHERE chain_id = ?`,
		chainID,
	).Scan(&eventCount); err != nil {
		return dashboardChain{}, 0, fmt.Errorf("count conftail dashboard chain events: %w", err)
	}
	totalPages := max(1, (eventCount+dashboardEventPageSize-1)/dashboardEventPageSize)
	if page > totalPages {
		return dashboardChain{}, totalPages, errDashboardPageRange
	}
	chain.Events, err = s.dashboardEventPage(ctx, chainID, page)
	if err != nil {
		return dashboardChain{}, 0, err
	}
	chain.VDOMs, chain.VDOMsOmitted, err = s.dashboardVDOMs(ctx, chainID)
	if err != nil {
		return dashboardChain{}, 0, err
	}
	return chain, totalPages, nil
}

func (s *store) dashboardEventPage(
	ctx context.Context,
	chainID string,
	page int,
) ([]dashboardEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		event_at_ns, source, device_name, device_id, vdom, user_attribution,
		ui, action, transaction_id, config_path, config_object, config_attribute,
		log_id, log_description, message, late
		FROM events WHERE chain_id = ?
		ORDER BY event_at_ns, id LIMIT ? OFFSET ?`,
		chainID,
		dashboardEventPageSize,
		(page-1)*dashboardEventPageSize,
	)
	if err != nil {
		return nil, fmt.Errorf("list conftail dashboard event page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	events := make([]dashboardEvent, 0, dashboardEventPageSize)
	for rows.Next() {
		event, scanErr := scanDashboardEvent(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan conftail dashboard event page: %w", scanErr)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate conftail dashboard event page: %w", err)
	}
	return events, nil
}

func (e *Extension) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filters, err := parseDashboardFilters(r.URL.Query())
	if err != nil {
		http.Error(w, "Invalid dashboard filters", http.StatusBadRequest)
		return
	}
	if e.store == nil || e.tmpl == nil {
		http.Error(w, "Configuration change dashboard unavailable", http.StatusServiceUnavailable)
		return
	}

	data, err := e.store.queryDashboard(r.Context(), filters)
	if err != nil {
		if e.logger != nil {
			e.logger.Error("conftail: dashboard query failed", "err", err)
		}
		http.Error(w, "Unable to load configuration change dashboard", http.StatusInternalServerError)
		return
	}
	for index := range data.Active {
		data.Active[index].QuietEligibleAt = data.Active[index].LastEventAt.Add(e.dashboardIdleDuration())
	}

	e.catalogMu.RLock()
	coverage := e.catalog.coverage()
	warnings := e.catalog.warnings()
	e.catalogMu.RUnlock()

	username := ""
	if e.currentUser != nil {
		username = e.currentUser(r)
	}
	page := dashboardPageData{
		Base:          e.conftailBaseData(username),
		Dashboard:     data,
		Filters:       dashboardFiltersView(filters),
		Health:        dashboardPollHealth(data.Poll, time.Now().UTC(), e.dashboardPollInterval()),
		NextPollRun:   dashboardNextPollRun(data.Poll, e.dashboardPollInterval()),
		Coverage:      coverage,
		Warnings:      warnings,
		ActiveOmitted: max(0, data.ActiveTotal-len(data.Active)),
	}
	if filters.Page > 1 {
		page.PrevURL = dashboardPageURL(filters, filters.Page-1)
	}
	if filters.Page < data.TotalPages {
		page.NextURL = dashboardPageURL(filters, filters.Page+1)
	}

	var output bytes.Buffer
	if err := e.tmpl.ExecuteTemplate(&output, "index.html", page); err != nil {
		if e.logger != nil {
			e.logger.Error("conftail: dashboard template failed", "err", err)
		}
		http.Error(w, "Unable to render configuration change dashboard", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = output.WriteTo(w)
}

func (e *Extension) dashboardChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	chainID, pageNumber, err := parseDashboardChainRequest(r)
	if err != nil {
		http.Error(w, "Invalid configuration change session", http.StatusBadRequest)
		return
	}
	if e.store == nil || e.tmpl == nil {
		http.Error(w, "Configuration change dashboard unavailable", http.StatusServiceUnavailable)
		return
	}
	chain, totalPages, err := e.store.dashboardChainPage(r.Context(), chainID, pageNumber)
	if errors.Is(err, errDashboardChainNotFound) {
		http.Error(w, "Configuration change session not found", http.StatusNotFound)
		return
	}
	if errors.Is(err, errDashboardPageRange) {
		http.Error(w, "Invalid configuration change session page", http.StatusBadRequest)
		return
	}
	if err != nil {
		e.logger.Error("conftail: chain dashboard query failed", "err", sanitizeDeliveryError(err))
		http.Error(w, "Unable to load configuration change session", http.StatusInternalServerError)
		return
	}
	if chain.State == chainStateActive {
		chain.QuietEligibleAt = chain.LastEventAt.Add(e.dashboardIdleDuration())
	}
	username := ""
	if e.currentUser != nil {
		username = e.currentUser(r)
	}
	view := dashboardChainPageData{
		Base:       e.conftailBaseData(username),
		Chain:      chain,
		Page:       pageNumber,
		TotalPages: totalPages,
	}
	if pageNumber > 1 {
		view.PrevURL = dashboardChainPageURL(chainID, pageNumber-1)
	}
	if pageNumber < totalPages {
		view.NextURL = dashboardChainPageURL(chainID, pageNumber+1)
	}
	var output bytes.Buffer
	if err := e.tmpl.ExecuteTemplate(&output, "chain.html", view); err != nil {
		e.logger.Error("conftail: chain dashboard template failed", "err", err)
		http.Error(w, "Unable to render configuration change session", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = output.WriteTo(w)
}

func parseDashboardChainRequest(r *http.Request) (string, int, error) {
	chainID := strings.TrimSpace(chi.URLParam(r, "chainID"))
	parsedID, err := uuid.Parse(chainID)
	if err != nil || parsedID == uuid.Nil || parsedID.String() != strings.ToLower(chainID) {
		return "", 0, errors.New("invalid chain id")
	}
	page := 1
	if value := strings.TrimSpace(r.URL.Query().Get("page")); value != "" {
		page, err = strconv.Atoi(value)
		if err != nil || page < 1 || page > dashboardMaxPage {
			return "", 0, errors.New("invalid chain page")
		}
	}
	return parsedID.String(), page, nil
}

func (e *Extension) conftailBaseData(username string) conftailBaseData {
	base := conftailBaseData{Username: username}
	if e.cfg == nil {
		return base
	}
	base.ExtAdmVPNEnabled = e.cfg.ExtAdmVpnConf
	base.ExtConfigGenEnabled = e.cfg.ExtFgtConfGen
	base.ExtPolSplitEnabled = e.cfg.ExtFgtPolSplit
	base.ExtConfConvEnabled = e.cfg.ExtFgtConfConv
	return base
}

func (e *Extension) dashboardPollInterval() time.Duration {
	if e.cfg == nil || e.cfg.FgtConfTailPollSeconds <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(e.cfg.FgtConfTailPollSeconds) * time.Second
}

func (e *Extension) dashboardIdleDuration() time.Duration {
	if e.cfg == nil || e.cfg.FgtConfTailIdleSeconds <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(e.cfg.FgtConfTailIdleSeconds) * time.Second
}

func dashboardNextPollRun(state PollState, interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	if !state.LastStartedAt.IsZero() {
		return state.LastStartedAt.Add(interval).UTC()
	}
	if !state.ActivationAt.IsZero() {
		return state.ActivationAt.Add(conftailPollFirstDelay).UTC()
	}
	return time.Time{}
}

func dashboardFiltersView(filters dashboardFilters) dashboardFilterView {
	view := dashboardFilterView{
		User:  filters.User,
		State: filters.State,
		Page:  filters.Page,
	}
	if filters.FirewallID > 0 {
		view.Firewall = strconv.Itoa(filters.FirewallID)
	}
	if !filters.From.IsZero() {
		view.From = filters.From.UTC().Format("2006-01-02T15:04")
	}
	if !filters.To.IsZero() {
		view.To = filters.To.UTC().Format("2006-01-02T15:04")
	}
	return view
}

func dashboardPollHealth(state PollState, now time.Time, interval time.Duration) dashboardHealth {
	if !state.LastFailureAt.IsZero() &&
		(state.LastSuccessAt.IsZero() || !state.LastFailureAt.Before(state.LastSuccessAt)) {
		return dashboardHealth{State: "failed", Label: "Poll failed", Detail: state.LastError}
	}
	if state.LastSuccessAt.IsZero() {
		return dashboardHealth{State: "waiting", Label: "Waiting for first poll"}
	}
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	if now.After(state.LastSuccessAt.Add(2 * interval)) {
		return dashboardHealth{State: "stale", Label: "Poll is stale"}
	}
	return dashboardHealth{State: "healthy", Label: "Polling healthy"}
}

func dashboardPageURL(filters dashboardFilters, page int) string {
	values := url.Values{}
	if filters.FirewallID > 0 {
		values.Set("firewall", strconv.Itoa(filters.FirewallID))
	}
	if filters.User != "" {
		values.Set("user", filters.User)
	}
	if filters.State != "" && filters.State != dashboardStateAll {
		values.Set("state", filters.State)
	}
	if !filters.From.IsZero() {
		values.Set("from", filters.From.UTC().Format("2006-01-02T15:04"))
	}
	if !filters.To.IsZero() {
		values.Set("to", filters.To.UTC().Format("2006-01-02T15:04"))
	}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	encoded := values.Encode()
	if encoded == "" {
		return "?"
	}
	return "?" + encoded
}

func dashboardChainPageURL(chainID string, page int) string {
	base := "/fgt-conftail/chain/" + chainID
	if page <= 1 {
		return base
	}
	return base + "?page=" + strconv.Itoa(page)
}

func formatDashboardTime(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	return value.UTC().Format("2006-01-02 15:04:05 UTC")
}

func formatDashboardDuration(value time.Duration) string {
	if value <= 0 {
		return "—"
	}
	return value.Round(time.Nanosecond).String()
}
