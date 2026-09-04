package fgtconftail

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
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
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/arumes31/fortigate-scp-backup/internal/webui"
)

const (
	dashboardStateAll               = "all"
	dashboardPageSize               = 25
	dashboardActiveLimit            = 100
	dashboardEventPageSize          = 100
	dashboardVDOMLimit              = 20
	dashboardMaxPage                = 10_000
	dashboardMaxFormBytes           = 32 << 10
	dashboardMaxPreviewBytes        = 2 << 20
	dashboardPreviewTextBytes       = 32 << 10
	dashboardChainViewChronological = "chronological"
	dashboardChainViewTransaction   = "transaction"
	dashboardChainViewObject        = "object"
	maxSearchRunes                  = 256
	maxSearchTerms                  = 10
	dashboardWhereSQL               = `c.state = ?
		AND (? = 0 OR EXISTS (SELECT 1 FROM events es
			JOIN event_search ON event_search.rowid = es.id
			WHERE es.chain_id = c.id AND event_search MATCH ?))
		AND (? = 0 OR c.firewall_id = ?)
		AND (? = 0 OR LOWER(c.user) LIKE LOWER(?) ESCAPE '\')
		AND (? = 0 OR EXISTS (SELECT 1 FROM events ef WHERE ef.chain_id = c.id
			AND LOWER(ef.source) LIKE LOWER(?) ESCAPE '\'))
		AND (? = 0 OR EXISTS (SELECT 1 FROM events ef WHERE ef.chain_id = c.id
			AND LOWER(ef.device_name) LIKE LOWER(?) ESCAPE '\'))
		AND (? = 0 OR EXISTS (SELECT 1 FROM events ef WHERE ef.chain_id = c.id
			AND LOWER(ef.device_id) LIKE LOWER(?) ESCAPE '\'))
		AND (? = 0 OR EXISTS (SELECT 1 FROM events ef WHERE ef.chain_id = c.id
			AND LOWER(ef.action) LIKE LOWER(?) ESCAPE '\'))
		AND (? = 0 OR EXISTS (SELECT 1 FROM events ef WHERE ef.chain_id = c.id
			AND ef.transaction_id = ?))
		AND (? = 0 OR EXISTS (SELECT 1 FROM events ef WHERE ef.chain_id = c.id
			AND ef.log_id = ?))
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

//go:embed templates/*.html static/*
var dashboardFS embed.FS

type dashboardFilters struct {
	FirewallID    int
	Search        string
	User          string
	Source        string
	Device        string
	Serial        string
	Action        string
	TransactionID string
	LogID         string
	State         string
	From          time.Time
	To            time.Time
	Page          int
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
	ID               int64
	Sequence         int
	EventAt          time.Time
	Source           string
	DeviceName       string
	DeviceID         string
	VDOM             string
	UserAttribution  string
	UI               string
	Action           string
	TransactionID    string
	Path             string
	Object           string
	ConfigAttribute  string
	AttributeDiff    configAttributeDiff
	HasAttributeDiff bool
	LogID            string
	LogDescription   string
	Message          string
	Late             bool
	GlobalIgnoreID   int64
	GlobalIgnoreKind string
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
	TicketPreview    dashboardTicketPreview
}

type dashboardTicketPreview struct {
	Summary     string
	Description string
	Unavailable bool
	Truncated   bool
}

type dashboardEventGroup struct {
	Label  string
	Events []dashboardEvent
}

type dashboardDeliverySummary struct {
	State      string
	Label      string
	Detail     string
	Action     string
	Attempts   int
	NextAt     time.Time
	AcceptedAt time.Time
	RequestID  string
	TicketURL  string
	LastError  string
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
	Firewall      string
	Search        string
	User          string
	Source        string
	Device        string
	Serial        string
	Action        string
	TransactionID string
	LogID         string
	State         string
	From          string
	To            string
	Page          int
}

type dashboardFormField struct {
	Name  string
	Value string
}

type dashboardFilterChip struct {
	Label  string
	Value  string
	Fields []dashboardFormField
}

type dashboardHealth struct {
	State     string
	Label     string
	Detail    string
	Evidence  string
	Action    string
	Code      diagnosticCode
	CheckedAt time.Time
}

type dashboardPageData struct {
	Base            webui.BaseData
	Dashboard       dashboardData
	Filters         dashboardFilterView
	Health          dashboardHealth
	SessionHealth   dashboardHealth
	DeliveryHealth  dashboardHealth
	NextPollRun     time.Time
	PollRunning     bool
	PollSignature   string
	CoverageEnabled bool
	Coverage        []sourceCoverage
	Firewalls       []sourceCoverage
	Warnings        []string
	ActiveOmitted   int
	IgnoreRules     []globalIgnoreRule
	IgnoreNotice    string
	ActiveFilters   []dashboardFilterChip
	AdvancedOpen    bool
	HasPrev         bool
	HasNext         bool
	PrevFields      []dashboardFormField
	NextFields      []dashboardFormField
}

type dashboardChainPageData struct {
	Base             webui.BaseData
	Chain            dashboardChain
	Delivery         dashboardDeliverySummary
	EventGroups      []dashboardEventGroup
	View             string
	ChronologicalURL string
	TransactionURL   string
	ObjectURL        string
	Page             int
	TotalPages       int
	PrevURL          string
	NextURL          string
	IgnoreNotice     string
}

type dashboardStatusResponse struct {
	Running   bool   `json:"running"`
	Signature string `json:"signature"`
}

func parseDashboardPages() (*webui.Renderer, *webui.Renderer, error) {
	funcs := template.FuncMap{
		"fmtTime":            formatDashboardTime,
		"fmtMachineTime":     formatDashboardMachineTime,
		"fmtDuration":        formatDashboardDuration,
		"fmtSessionDuration": formatDashboardSessionDuration,
	}
	indexPage, err := webui.ParsePage(dashboardFS, "templates/index.html", funcs)
	if err != nil {
		return nil, nil, err
	}
	chainPage, err := webui.ParsePage(dashboardFS, "templates/chain.html", funcs)
	if err != nil {
		return nil, nil, err
	}
	return indexPage, chainPage, nil
}

func dashboardStaticFS() (fs.FS, error) {
	return fs.Sub(dashboardFS, "static")
}

func parseDashboardFilters(values url.Values) (dashboardFilters, error) {
	filters := dashboardFilters{
		Search:        strings.TrimSpace(values.Get("q")),
		User:          strings.TrimSpace(values.Get("user")),
		Source:        strings.TrimSpace(values.Get("source")),
		Device:        strings.TrimSpace(values.Get("device")),
		Serial:        strings.TrimSpace(values.Get("serial")),
		Action:        strings.TrimSpace(values.Get("action")),
		TransactionID: strings.TrimSpace(values.Get("transaction")),
		LogID:         strings.TrimSpace(values.Get("log_id")),
		State:         strings.TrimSpace(values.Get("state")),
		Page:          1,
	}
	if filters.State == "" {
		filters.State = dashboardStateAll
	}
	if _, err := compileDashboardSearch(filters.Search); err != nil {
		return dashboardFilters{}, fmt.Errorf("invalid dashboard search: %w", err)
	}
	for _, filter := range []struct {
		name  string
		value string
	}{
		{name: "user", value: filters.User},
		{name: "source", value: filters.Source},
		{name: "device", value: filters.Device},
		{name: "serial", value: filters.Serial},
		{name: "action", value: filters.Action},
		{name: "transaction", value: filters.TransactionID},
		{name: "log id", value: filters.LogID},
	} {
		if err := validateDashboardTextFilter(filter.value); err != nil {
			return dashboardFilters{}, fmt.Errorf("invalid dashboard %s filter: %w", filter.name, err)
		}
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

var dashboardFilterKeys = map[string]bool{
	"firewall": true, "q": true, "user": true, "source": true,
	"device": true, "serial": true, "action": true, "transaction": true,
	"log_id": true, "state": true, "from": true, "to": true, "page": true,
}

var dashboardGETKeys = map[string]bool{
	"firewall": true, "state": true, "from": true, "to": true,
	"page": true, "ignore": true,
}

func validateDashboardKeys(values url.Values, allowed map[string]bool) error {
	for key, entries := range values {
		if !allowed[key] {
			return fmt.Errorf("dashboard parameter %q is not allowed", key)
		}
		if len(entries) != 1 {
			return fmt.Errorf("dashboard parameter %q must occur exactly once", key)
		}
	}
	return nil
}

func parseDashboardRequest(w http.ResponseWriter, r *http.Request) (dashboardFilters, error) {
	switch r.Method {
	case http.MethodGet:
		if err := validateDashboardKeys(r.URL.Query(), dashboardGETKeys); err != nil {
			return dashboardFilters{}, err
		}
		return parseDashboardFilters(r.URL.Query())
	case http.MethodPost:
		if len(r.URL.Query()) != 0 {
			return dashboardFilters{}, errors.New("dashboard POST query parameters are not allowed")
		}
		r.Body = http.MaxBytesReader(w, r.Body, dashboardMaxFormBytes)
		if err := r.ParseForm(); err != nil {
			return dashboardFilters{}, fmt.Errorf("parse dashboard form: %w", err)
		}
		if err := validateDashboardKeys(r.PostForm, dashboardFilterKeys); err != nil {
			return dashboardFilters{}, err
		}
		return parseDashboardFilters(r.PostForm)
	default:
		return dashboardFilters{}, errors.New("dashboard method is not allowed")
	}
}

func validateDashboardTextFilter(value string) error {
	if utf8.RuneCountInString(value) > maxIdentityRunes {
		return errors.New("value is too long")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return errors.New("value contains a control character")
		}
	}
	return nil
}

func compileDashboardSearch(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if utf8.RuneCountInString(value) > maxSearchRunes {
		return "", errors.New("value is too long")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", errors.New("value contains a control character")
		}
	}
	terms := strings.Fields(value)
	if len(terms) > maxSearchTerms {
		return "", fmt.Errorf("search exceeds the %d-term limit", maxSearchTerms)
	}
	quoted := make([]string, 0, len(terms))
	for _, term := range terms {
		quoted = append(quoted, `"`+strings.ReplaceAll(term, `"`, `""`)+`"`)
	}
	return strings.Join(quoted, " AND "), nil
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
	if _, err := compileDashboardSearch(filters.Search); err != nil {
		return dashboardData{}, fmt.Errorf("invalid conftail dashboard search: %w", err)
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
	searchQuery, _ := compileDashboardSearch(filters.Search)
	return []any{
		chainState,
		boolInt(searchQuery != ""), searchQuery,
		boolInt(filters.FirewallID > 0), filters.FirewallID,
		boolInt(filters.User != ""), "%" + escapeDashboardLike(filters.User) + "%",
		boolInt(filters.Source != ""), "%" + escapeDashboardLike(filters.Source) + "%",
		boolInt(filters.Device != ""), "%" + escapeDashboardLike(filters.Device) + "%",
		boolInt(filters.Serial != ""), "%" + escapeDashboardLike(filters.Serial) + "%",
		boolInt(filters.Action != ""), "%" + escapeDashboardLike(filters.Action) + "%",
		boolInt(filters.TransactionID != ""), filters.TransactionID,
		boolInt(filters.LogID != ""), filters.LogID,
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
		&event.ID,
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
	event.AttributeDiff, event.HasAttributeDiff = parseConfigAttributeDiff(event.ConfigAttribute)
	return event, nil
}

func (s *store) dashboardVDOMs(ctx context.Context, chainID string) ([]string, int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT vdom, COUNT(*) OVER () FROM events
		WHERE chain_id = ? AND vdom != '' GROUP BY vdom ORDER BY vdom LIMIT ?`,
		chainID, dashboardVDOMLimit+1)
	if err != nil {
		return nil, 0, fmt.Errorf("list conftail dashboard VDOMs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	vdoms := make([]string, 0, dashboardVDOMLimit)
	distinctCount := 0
	for rows.Next() {
		var vdom string
		if err := rows.Scan(&vdom, &distinctCount); err != nil {
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
		omitted = distinctCount - len(vdoms)
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
	for eventIndex := range chain.Events {
		chain.Events[eventIndex].Sequence = (page-1)*dashboardEventPageSize + eventIndex + 1
	}
	chain.VDOMs, chain.VDOMsOmitted, err = s.dashboardVDOMs(ctx, chainID)
	if err != nil {
		return dashboardChain{}, 0, err
	}
	chain.TicketPreview, err = s.dashboardTicketPreview(ctx, chainID)
	if err != nil {
		return dashboardChain{}, 0, err
	}
	return chain, totalPages, nil
}

func (s *store) dashboardTicketPreview(ctx context.Context, chainID string) (dashboardTicketPreview, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT payload_json FROM outbox WHERE chain_id = ?`, chainID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return dashboardTicketPreview{}, nil
	}
	if err != nil {
		return dashboardTicketPreview{}, fmt.Errorf("read conftail ticket preview: %w", err)
	}
	if len(payload) == 0 || len(payload) > dashboardMaxPreviewBytes {
		return dashboardTicketPreview{Unavailable: true}, nil
	}
	var frozen struct {
		Summary     string `json:"summary"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(payload, &frozen); err != nil || strings.TrimSpace(frozen.Description) == "" {
		return dashboardTicketPreview{Unavailable: true}, nil
	}
	description := truncateUTF8Bytes(frozen.Description, dashboardPreviewTextBytes)
	return dashboardTicketPreview{
		Summary:     sanitizeExternalString(frozen.Summary, 255),
		Description: description,
		Truncated:   len(description) < len(frozen.Description),
	}, nil
}

func (s *store) dashboardEventPage(
	ctx context.Context,
	chainID string,
	page int,
) ([]dashboardEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		id, event_at_ns, source, device_name, device_id, vdom, user_attribution,
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
	startedAt := time.Now()
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filters, err := parseDashboardRequest(w, r)
	if err != nil {
		if e.logger != nil {
			e.logger.WarnContext(r.Context(), "conftail dashboard query rejected",
				"code", codeDashboardQueryFailed, "outcome", "invalid",
				"duration_ms", time.Since(startedAt).Milliseconds(), "reqid", middleware.GetReqID(r.Context()))
		}
		http.Error(w, "Invalid dashboard filters", http.StatusBadRequest)
		return
	}
	if e.store == nil || e.indexPage == nil || e.pageBase == nil {
		http.Error(w, "Configuration change dashboard unavailable", http.StatusServiceUnavailable)
		return
	}

	data, err := e.store.queryDashboard(r.Context(), filters)
	if err != nil {
		if e.logger != nil {
			e.logger.ErrorContext(r.Context(), "conftail: dashboard query failed",
				"code", codeDashboardQueryFailed, "outcome", "error", "err", err,
				"duration_ms", time.Since(startedAt).Milliseconds(), "page", filters.Page,
				"reqid", middleware.GetReqID(r.Context()))
		}
		http.Error(w, "Unable to load configuration change dashboard", http.StatusInternalServerError)
		return
	}
	if err := e.store.observeDashboardQuery(r.Context(), filters, time.Now().UTC()); err != nil && e.logger != nil {
		e.logger.Warn("conftail managed index observation failed", "code", codeIndexMaintenanceFailed, "err", err)
	}
	for index := range data.Active {
		data.Active[index].QuietEligibleAt = data.Active[index].LastEventAt.Add(e.dashboardIdleDuration())
	}
	ignoreRules, err := e.store.listGlobalIgnoreRules(r.Context())
	if err != nil {
		if e.logger != nil {
			e.logger.Error("conftail: global ignore query failed", "code", codeDashboardQueryFailed, "err", err)
		}
		http.Error(w, "Unable to load global ignore rules", http.StatusInternalServerError)
		return
	}

	e.catalogMu.RLock()
	coverage := e.catalog.coverage()
	warnings := e.catalog.warnings()
	e.catalogMu.RUnlock()

	now := time.Now().UTC()
	pollInterval := adaptivePollInterval(data.Poll, data.Poll.LastIngestedAt, now)
	page := dashboardPageData{
		Base:            e.pageBase(r, "Configuration Change Tail", "conftail"),
		Dashboard:       data,
		Filters:         dashboardFiltersView(filters),
		Health:          dashboardPollHealth(data.Poll, now, pollInterval),
		SessionHealth:   dashboardSessionHealth(data.Counts, now),
		DeliveryHealth:  dashboardDeliveryHealth(data.Counts, now),
		NextPollRun:     dashboardNextPollRun(data.Poll, pollInterval),
		PollRunning:     dashboardPollRunning(data.Poll),
		PollSignature:   dashboardPollSignature(data.Poll),
		CoverageEnabled: e.cfg != nil && e.cfg.ExtAdmVpnConf,
		Coverage:        coverage,
		Firewalls:       coverage,
		Warnings:        warnings,
		ActiveOmitted:   max(0, data.ActiveTotal-len(data.Active)),
		IgnoreRules:     ignoreRules,
		IgnoreNotice:    dashboardIgnoreNotice(r.URL.Query().Get("ignore")),
		ActiveFilters:   dashboardActiveFilterChips(filters),
		AdvancedOpen:    dashboardAdvancedFiltersSet(filters),
	}
	if filters.Page > 1 {
		page.HasPrev = true
		page.PrevFields = dashboardFormFields(filters, filters.Page-1, "")
	}
	if filters.Page < data.TotalPages {
		page.HasNext = true
		page.NextFields = dashboardFormFields(filters, filters.Page+1, "")
	}

	var output bytes.Buffer
	if err := e.indexPage.Render(&output, page); err != nil {
		if e.logger != nil {
			e.logger.Error("conftail: dashboard template failed", "code", codeDashboardRenderFailed, "err", err)
		}
		http.Error(w, "Unable to render configuration change dashboard", http.StatusInternalServerError)
		return
	}
	if e.logger != nil {
		e.logger.InfoContext(
			r.Context(),
			"conftail dashboard queried",
			"code", codeDashboardQueried,
			"outcome", "success",
			"firewall_filter_set", filters.FirewallID > 0,
			"search_filter_set", filters.Search != "",
			"user_filter_set", filters.User != "",
			"source_filter_set", filters.Source != "",
			"device_filter_set", filters.Device != "",
			"serial_filter_set", filters.Serial != "",
			"action_filter_set", filters.Action != "",
			"transaction_filter_set", filters.TransactionID != "",
			"log_id_filter_set", filters.LogID != "",
			"state_filter_set", filters.State != "" && filters.State != dashboardStateAll,
			"from_filter_set", !filters.From.IsZero(),
			"to_filter_set", !filters.To.IsZero(),
			"page", filters.Page,
			"active_rows", len(data.Active),
			"history_rows", len(data.History),
			"result_count", len(data.Active)+len(data.History),
			"active_total", data.ActiveTotal,
			"history_total", data.HistoryTotal,
			"duration_ms", time.Since(startedAt).Milliseconds(),
			"reqid", middleware.GetReqID(r.Context()),
		)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = output.WriteTo(w)
}

func (e *Extension) dashboardStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if e.store == nil {
		http.Error(w, "Configuration change dashboard unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := e.store.pollState(r.Context())
	if err != nil {
		if e.logger != nil {
			e.logger.Error("conftail: dashboard status query failed", "code", codeDashboardQueryFailed, "err", err)
		}
		http.Error(w, "Unable to load configuration change status", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(dashboardStatusResponse{
		Running:   dashboardPollRunning(state),
		Signature: dashboardPollSignature(state),
	}); err != nil && e.logger != nil {
		e.logger.Warn("conftail: dashboard status response failed", "code", codeDashboardRenderFailed, "err", err)
	}
}

func (e *Extension) dashboardChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	chainID, pageNumber, viewMode, err := parseDashboardChainRequest(r)
	if err != nil {
		http.Error(w, "Invalid configuration change session", http.StatusBadRequest)
		return
	}
	if e.store == nil || e.chainPage == nil || e.pageBase == nil {
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
		if e.logger != nil {
			e.logger.Error("conftail: chain dashboard query failed", "code", codeSessionQueryFailed, "err", sanitizeDeliveryError(err))
		}
		http.Error(w, "Unable to load configuration change session", http.StatusInternalServerError)
		return
	}
	if chain.State == chainStateActive {
		chain.QuietEligibleAt = chain.LastEventAt.Add(e.dashboardIdleDuration())
	}
	ignoreRules, err := e.store.listGlobalIgnoreRules(r.Context())
	if err != nil {
		if e.logger != nil {
			e.logger.Error("conftail: session global ignore query failed", "code", codeSessionQueryFailed, "err", sanitizeDeliveryError(err))
		}
		http.Error(w, "Unable to load global ignore rules", http.StatusInternalServerError)
		return
	}
	for eventIndex := range chain.Events {
		event := &chain.Events[eventIndex]
		candidate := Event{Action: event.Action, Path: event.Path, ConfigAttribute: event.ConfigAttribute}
		if rule, ok := matchingGlobalIgnoreRule(ignoreRules, candidate); ok {
			event.GlobalIgnoreID = rule.ID
			event.GlobalIgnoreKind = rule.Kind
		}
	}
	username := ""
	if e.currentUser != nil {
		username = e.currentUser(r)
	}
	view := dashboardChainPageData{
		Base:             e.pageBase(r, "Configuration Change Session", "conftail"),
		Chain:            chain,
		Delivery:         buildDashboardDeliverySummary(chain),
		EventGroups:      dashboardEventGroups(chain.Events, viewMode),
		View:             viewMode,
		ChronologicalURL: dashboardChainPageURL(chainID, pageNumber, dashboardChainViewChronological),
		TransactionURL:   dashboardChainPageURL(chainID, pageNumber, dashboardChainViewTransaction),
		ObjectURL:        dashboardChainPageURL(chainID, pageNumber, dashboardChainViewObject),
		Page:             pageNumber,
		TotalPages:       totalPages,
		IgnoreNotice:     dashboardIgnoreNotice(r.URL.Query().Get("ignore")),
	}
	if pageNumber > 1 {
		view.PrevURL = dashboardChainPageURL(chainID, pageNumber-1, viewMode)
	}
	if pageNumber < totalPages {
		view.NextURL = dashboardChainPageURL(chainID, pageNumber+1, viewMode)
	}
	var output bytes.Buffer
	if err := e.chainPage.Render(&output, view); err != nil {
		if e.logger != nil {
			e.logger.Error("conftail: chain dashboard template failed", "code", codeDashboardRenderFailed, "err", err)
		}
		http.Error(w, "Unable to render configuration change session", http.StatusInternalServerError)
		return
	}
	if e.logger != nil {
		e.logger.InfoContext(
			r.Context(),
			"conftail session queried",
			"code", codeSessionQueried,
			"actor", sanitizeExternalString(username, maxIdentityRunes),
			"chain_id", chainID,
			"state", chain.State,
			"view", viewMode,
			"page", pageNumber,
			"total_pages", totalPages,
			"event_rows", len(chain.Events),
			"reqid", middleware.GetReqID(r.Context()),
		)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = output.WriteTo(w)
}

func dashboardIgnoreNotice(value string) string {
	switch value {
	case "created":
		return "Global ignore rule created. Future matching events will not enter sessions or tickets."
	case "updated":
		return "Global ignore rule status updated."
	case "deleted":
		return "Global ignore rule deleted. Previously ignored events remain suppressed."
	default:
		return ""
	}
}

func parseDashboardChainRequest(r *http.Request) (string, int, string, error) {
	chainID := strings.TrimSpace(chi.URLParam(r, "chainID"))
	parsedID, err := uuid.Parse(chainID)
	if err != nil || parsedID == uuid.Nil || parsedID.String() != strings.ToLower(chainID) {
		return "", 0, "", errors.New("invalid chain id")
	}
	if err := validateDashboardKeys(r.URL.Query(), map[string]bool{
		"page": true, "view": true, "ignore": true,
	}); err != nil {
		return "", 0, "", err
	}
	page := 1
	if value := strings.TrimSpace(r.URL.Query().Get("page")); value != "" {
		page, err = strconv.Atoi(value)
		if err != nil || page < 1 || page > dashboardMaxPage {
			return "", 0, "", errors.New("invalid chain page")
		}
	}
	view, err := normalizeDashboardChainView(r.URL.Query().Get("view"))
	if err != nil {
		return "", 0, "", err
	}
	ignoreNotice := strings.TrimSpace(r.URL.Query().Get("ignore"))
	if ignoreNotice != "" && dashboardIgnoreNotice(ignoreNotice) == "" {
		return "", 0, "", errors.New("invalid chain ignore notice")
	}
	return parsedID.String(), page, view, nil
}

func normalizeDashboardChainView(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return dashboardChainViewChronological, nil
	}
	switch value {
	case dashboardChainViewChronological, dashboardChainViewTransaction, dashboardChainViewObject:
		return value, nil
	default:
		return "", errors.New("invalid chain view")
	}
}

func dashboardEventGroups(events []dashboardEvent, view string) []dashboardEventGroup {
	if view == dashboardChainViewChronological || len(events) == 0 {
		return nil
	}
	groups := make([]dashboardEventGroup, 0)
	indexes := make(map[string]int)
	for _, event := range events {
		key, label := dashboardEventGroupIdentity(event, view)
		groupIndex, exists := indexes[key]
		if !exists {
			groupIndex = len(groups)
			indexes[key] = groupIndex
			groups = append(groups, dashboardEventGroup{Label: label})
		}
		groups[groupIndex].Events = append(groups[groupIndex].Events, event)
	}
	return groups
}

func dashboardEventGroupIdentity(event dashboardEvent, view string) (string, string) {
	if view == dashboardChainViewTransaction {
		transactionID := strings.TrimSpace(event.TransactionID)
		if transactionID == "" {
			return "transaction:none", "Without transaction ID"
		}
		return "transaction:" + transactionID, "Transaction " + transactionID
	}
	path := strings.TrimSpace(event.Path)
	object := strings.TrimSpace(event.Object)
	if path == "" {
		path = "Unknown path"
	}
	label := path
	if object != "" && object != "-" {
		label += " / " + object
	}
	return "object:" + path + "\x00" + object, label
}

func buildDashboardDeliverySummary(chain dashboardChain) dashboardDeliverySummary {
	summary := dashboardDeliverySummary{
		State: chain.DeliveryState, Attempts: chain.DeliveryAttempts,
		NextAt: chain.NextAttemptAt, AcceptedAt: chain.AcceptedAt,
		RequestID: chain.RequestID, TicketURL: dashboardSafeTicketURL(chain.RequestID),
		LastError: chain.LastError,
	}
	if chain.State == chainStateActive {
		summary.State = "waiting"
		summary.Label = "Not queued"
		summary.Detail = "This session is still collecting changes."
		return summary
	}
	switch chain.DeliveryState {
	case deliveryStatePending:
		summary.Label = "Queued"
		summary.Detail = "The immutable ticket is waiting for delivery."
	case deliveryStateRetry:
		summary.Label = "Retry scheduled"
		summary.Detail = "Hookwise delivery will retry automatically."
		summary.Action = "Check the next attempt and the last classified error."
	case deliveryStateFailed:
		summary.Label = "Delivery failed"
		summary.Detail = "Automatic delivery stopped after a non-retryable failure."
		summary.Action = "Check Hookwise authentication, endpoint configuration, and application logs."
	case deliveryStateAccepted:
		summary.Label = "Accepted by Hookwise"
		summary.Detail = "Hookwise accepted the immutable ticket payload."
	default:
		summary.State = "waiting"
		summary.Label = "No delivery record"
		summary.Detail = "No Hookwise delivery record is available for this sealed session."
		summary.Action = "Check the sealing worker and application logs."
	}
	return summary
}

func dashboardSafeTicketURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Opaque != "" {
		return ""
	}
	return parsed.String()
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

func dashboardPollRunning(state PollState) bool {
	if state.LastStartedAt.IsZero() {
		return false
	}
	lastCompletedAt := state.LastSuccessAt
	if state.LastFailureAt.After(lastCompletedAt) {
		lastCompletedAt = state.LastFailureAt
	}
	return lastCompletedAt.Before(state.LastStartedAt)
}

func dashboardPollSignature(state PollState) string {
	return fmt.Sprintf(
		"%d:%d:%d",
		unixNanos(state.LastStartedAt),
		unixNanos(state.LastSuccessAt),
		unixNanos(state.LastFailureAt),
	)
}

func dashboardFiltersView(filters dashboardFilters) dashboardFilterView {
	view := dashboardFilterView{
		Search:        filters.Search,
		User:          filters.User,
		Source:        filters.Source,
		Device:        filters.Device,
		Serial:        filters.Serial,
		Action:        filters.Action,
		TransactionID: filters.TransactionID,
		LogID:         filters.LogID,
		State:         filters.State,
		Page:          filters.Page,
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

func dashboardFormFields(filters dashboardFilters, page int, omit string) []dashboardFormField {
	view := dashboardFiltersView(filters)
	fields := make([]dashboardFormField, 0, 13)
	add := func(name, value string) {
		if name != omit && value != "" {
			fields = append(fields, dashboardFormField{Name: name, Value: value})
		}
	}
	add("firewall", view.Firewall)
	add("q", view.Search)
	add("user", view.User)
	add("source", view.Source)
	add("device", view.Device)
	add("serial", view.Serial)
	add("action", view.Action)
	add("transaction", view.TransactionID)
	add("log_id", view.LogID)
	if view.State != dashboardStateAll {
		add("state", view.State)
	}
	add("from", view.From)
	add("to", view.To)
	if page > 1 && omit != "page" {
		fields = append(fields, dashboardFormField{Name: "page", Value: strconv.Itoa(page)})
	}
	return fields
}

func dashboardActiveFilterChips(filters dashboardFilters) []dashboardFilterChip {
	view := dashboardFiltersView(filters)
	stateValue := view.State
	if stateValue == dashboardStateAll {
		stateValue = ""
	}
	definitions := []struct {
		name  string
		label string
		value string
	}{
		{name: "firewall", label: "Firewall", value: view.Firewall},
		{name: "q", label: "Search", value: view.Search},
		{name: "user", label: "Administrator", value: view.User},
		{name: "state", label: "State", value: stateValue},
		{name: "from", label: "From", value: view.From},
		{name: "to", label: "Through", value: view.To},
		{name: "source", label: "Source", value: view.Source},
		{name: "device", label: "Device", value: view.Device},
		{name: "serial", label: "Serial", value: view.Serial},
		{name: "action", label: "Action", value: view.Action},
		{name: "transaction", label: "Transaction", value: view.TransactionID},
		{name: "log_id", label: "Log ID", value: view.LogID},
	}
	chips := make([]dashboardFilterChip, 0, len(definitions))
	for _, definition := range definitions {
		if definition.value == "" {
			continue
		}
		chips = append(chips, dashboardFilterChip{
			Label: definition.label, Value: definition.value,
			Fields: dashboardFormFields(filters, 1, definition.name),
		})
	}
	return chips
}

func dashboardAdvancedFiltersSet(filters dashboardFilters) bool {
	return filters.Source != "" || filters.Device != "" || filters.Serial != "" || filters.Action != "" ||
		filters.TransactionID != "" || filters.LogID != ""
}

func dashboardPollHealth(state PollState, now time.Time, interval time.Duration) dashboardHealth {
	checkedAt := state.LastStartedAt
	if state.LastSuccessAt.After(checkedAt) {
		checkedAt = state.LastSuccessAt
	}
	if state.LastFailureAt.After(checkedAt) {
		checkedAt = state.LastFailureAt
	}
	evidence := fmt.Sprintf("%d page(s) / %d fetched / %d inserted", state.LastPages, state.LastFetched, state.LastInserted)
	if dashboardPollRunning(state) {
		return dashboardHealth{
			State: "waiting", Label: "Collector polling", Detail: "Graylog query in progress",
			Evidence: evidence, CheckedAt: checkedAt,
		}
	}
	if !state.LastFailureAt.IsZero() &&
		(state.LastSuccessAt.IsZero() || !state.LastFailureAt.Before(state.LastSuccessAt)) {
		return dashboardHealth{
			State:  "failed",
			Label:  "Collector failed",
			Detail: state.LastError,
			Action: dashboardPollRemediation(state.LastError),
			Code:   codeGraylogPollFailed, Evidence: evidence, CheckedAt: checkedAt,
		}
	}
	if state.LastSuccessAt.IsZero() {
		return dashboardHealth{
			State:  "waiting",
			Label:  "Collector waiting",
			Action: "Wait for the first scheduled poll; check the scheduler if this persists.", CheckedAt: checkedAt,
		}
	}
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	if now.After(state.LastSuccessAt.Add(2 * interval)) {
		return dashboardHealth{
			State:  "stale",
			Label:  "Collector is stale",
			Action: "Check the ConfTail poll scheduler and recent application logs.", Evidence: evidence, CheckedAt: checkedAt,
		}
	}
	return dashboardHealth{State: "healthy", Label: "Collector healthy", Evidence: evidence, CheckedAt: checkedAt}
}

func dashboardPollRemediation(lastError string) string {
	normalized := strings.ToLower(lastError)
	switch {
	case strings.Contains(normalized, "http 401"), strings.Contains(normalized, "http 403"):
		return "Verify the Graylog token and its search permissions."
	case strings.Contains(normalized, "http 429"):
		return "Graylog is throttling requests; automatic retries honor Retry-After."
	case strings.Contains(normalized, "schema"), strings.Contains(normalized, "decode graylog"),
		strings.Contains(normalized, "eventtime"):
		return "Check the Graylog field mapping and search response schema."
	case strings.Contains(normalized, "no queryable aliases"):
		return "Enable Graylog for at least one ADM VPN firewall and verify source aliases."
	case strings.Contains(normalized, "timeout"), strings.Contains(normalized, "deadline"):
		return "Check Graylog latency and the ConfTail poll timeout."
	default:
		return "Check Graylog connectivity, URL configuration, and the application log."
	}
}

func dashboardSessionHealth(counts dashboardCounts, checkedAt time.Time) dashboardHealth {
	return dashboardHealth{
		State: "healthy", Label: "Background processing healthy",
		Evidence: fmt.Sprintf("%d active / %d sealed", counts.Active, counts.Sealed), CheckedAt: checkedAt,
	}
}

func dashboardDeliveryHealth(counts dashboardCounts, checkedAt time.Time) dashboardHealth {
	switch {
	case counts.Failed > 0:
		return dashboardHealth{
			State:    "failed",
			Label:    "Hookwise delivery failed",
			Evidence: fmt.Sprintf("%d failed / %d retry", counts.Failed, counts.Retry),
			Action:   "Check the Hookwise endpoint, token, and failed delivery details.",
			Code:     codeHookwiseDeliveryFailed, CheckedAt: checkedAt,
		}
	case counts.Retry > 0:
		return dashboardHealth{
			State:     "waiting",
			Label:     "Hookwise retrying",
			Evidence:  fmt.Sprintf("%d retry / %d pending", counts.Retry, counts.Pending),
			Action:    "Retries are automatic; inspect delivery details if the queue keeps growing.",
			CheckedAt: checkedAt,
		}
	case counts.Pending > 0:
		return dashboardHealth{
			State:    "waiting",
			Label:    "Hookwise queued",
			Evidence: fmt.Sprintf("%d pending", counts.Pending), CheckedAt: checkedAt,
		}
	default:
		return dashboardHealth{
			State:    "healthy",
			Label:    "Hookwise delivery healthy",
			Evidence: fmt.Sprintf("%d accepted", counts.Accepted), CheckedAt: checkedAt,
		}
	}
}

func dashboardChainPageURL(chainID string, page int, view string) string {
	base := "/fgt-conftail/chain/" + chainID
	values := url.Values{}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	if view != "" && view != dashboardChainViewChronological {
		values.Set("view", view)
	}
	if len(values) == 0 {
		return base
	}
	return base + "?" + values.Encode()
}

func formatDashboardTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format("2006-01-02 15:04:05 UTC")
}

func formatDashboardMachineTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func formatDashboardDuration(value time.Duration) string {
	if value <= 0 {
		return "-"
	}
	return value.Round(time.Nanosecond).String()
}

func formatDashboardSessionDuration(start, end time.Time) string {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return "-"
	}
	return end.Sub(start).Round(time.Second).String()
}
