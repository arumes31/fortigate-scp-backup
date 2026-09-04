package fgtconftail

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

const (
	sessionExportJSON          = "json"
	sessionExportCSV           = "csv"
	sessionExportSchemaVersion = 1

	defaultSessionExportMaxRows  = 10_000
	defaultSessionExportMaxBytes = 16 << 20
	defaultSessionExportPageSize = 500
	defaultSessionExportTimeout  = 15 * time.Second

	sessionExportCSVSourceColumn = 6
)

var (
	errSessionExportNotFound  = errors.New("conftail export session not found")
	errSessionExportRowLimit  = errors.New("conftail export row limit exceeded")
	errSessionExportByteLimit = errors.New("conftail export byte limit exceeded")
	errSessionExportUnsafe    = errors.New("conftail export contains unsafe stored data")

	sessionExportCSVHeader = []string{
		"sequence", "event_id", "event_at", "firewall_id", "firewall_name",
		"administrator", "source", "device_name", "serial", "vdom",
		"attribution", "ui", "action", "transaction_id", "path", "object",
		"attribute", "log_id", "description", "message", "late",
	}
)

type sessionExportLimits struct {
	MaxRows  int
	MaxBytes int
	PageSize int
	Timeout  time.Duration
}

func defaultSessionExportLimits() sessionExportLimits {
	return sessionExportLimits{
		MaxRows:  defaultSessionExportMaxRows,
		MaxBytes: defaultSessionExportMaxBytes,
		PageSize: defaultSessionExportPageSize,
		Timeout:  defaultSessionExportTimeout,
	}
}

func (limits sessionExportLimits) normalized() sessionExportLimits {
	defaults := defaultSessionExportLimits()
	if limits.MaxRows <= 0 {
		limits.MaxRows = defaults.MaxRows
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = defaults.MaxBytes
	}
	if limits.PageSize <= 0 || limits.PageSize > limits.MaxRows {
		limits.PageSize = min(defaults.PageSize, limits.MaxRows)
	}
	if limits.Timeout <= 0 {
		limits.Timeout = defaults.Timeout
	}
	return limits
}

type sessionExportBuffer struct {
	bytes.Buffer
	maxBytes int
}

func (buffer *sessionExportBuffer) Write(value []byte) (int, error) {
	if len(value) > buffer.maxBytes-buffer.Len() {
		return 0, errSessionExportByteLimit
	}
	return buffer.Buffer.Write(value)
}

type sessionExportStats struct {
	Pages int
	Rows  int
	Bytes int
}

type sessionExportDocument struct {
	SchemaVersion int                   `json:"schema_version"`
	Session       sessionExportMetadata `json:"session"`
}

type sessionExportMetadata struct {
	ID              string `json:"id"`
	FirewallID      int    `json:"firewall_id"`
	FirewallName    string `json:"firewall_name"`
	Administrator   string `json:"administrator"`
	StartedAt       string `json:"started_at"`
	EndedAt         string `json:"ended_at"`
	State           string `json:"state"`
	DeliveryState   string `json:"delivery_state"`
	TicketRequestID string `json:"ticket_request_id,omitempty"`
	ChangeCount     int    `json:"change_count"`
	ExportedCount   int    `json:"exported_count"`
	Late            bool   `json:"late"`
	Unattributed    bool   `json:"unattributed"`
}

type sessionExportEvent struct {
	Sequence        int    `json:"sequence"`
	EventID         int64  `json:"event_id"`
	EventAt         string `json:"event_at"`
	Source          string `json:"source"`
	DeviceName      string `json:"device_name"`
	Serial          string `json:"serial"`
	VDOM            string `json:"vdom"`
	Attribution     string `json:"attribution"`
	UI              string `json:"ui"`
	Action          string `json:"action"`
	TransactionID   string `json:"transaction_id"`
	Path            string `json:"path"`
	Object          string `json:"object"`
	ConfigAttribute string `json:"attribute"`
	LogID           string `json:"log_id"`
	Description     string `json:"description"`
	Message         string `json:"message"`
	Late            bool   `json:"late"`
}

func (e *Extension) exportSession(w http.ResponseWriter, r *http.Request) {
	startedAt := time.Now()
	chainID, format, err := parseSessionExportRequest(r)
	stats := sessionExportStats{}
	outcome := "invalid"
	if err != nil {
		http.Error(w, "Invalid configuration change export request", http.StatusBadRequest)
		e.recordSessionExport(r, "", "", stats, outcome, startedAt)
		return
	}
	if e.store == nil || e.store.db == nil {
		http.Error(w, "Configuration change export unavailable", http.StatusServiceUnavailable)
		e.recordSessionExport(r, chainID, format, stats, "unavailable", startedAt)
		return
	}

	limits := e.exportLimits.normalized()
	ctx, cancel := context.WithTimeout(r.Context(), limits.Timeout)
	defer cancel()
	buffer, exportStats, exportErr := e.buildSessionExport(ctx, chainID, format, limits)
	stats = exportStats
	if exportErr != nil {
		status, message, errorOutcome := sessionExportErrorResponse(exportErr)
		http.Error(w, message, status)
		e.recordSessionExport(r, chainID, format, stats, errorOutcome, startedAt)
		return
	}

	filename := "fortisafe-conftail-" + chainID + "." + format
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(buffer.Len()))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if format == sessionExportJSON {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = buffer.WriteTo(w)
	e.recordSessionExport(r, chainID, format, stats, "success", startedAt)
}

func parseSessionExportRequest(r *http.Request) (string, string, error) {
	chainID := strings.TrimSpace(chi.URLParam(r, "chainID"))
	parsedID, err := uuid.Parse(chainID)
	if err != nil || parsedID == uuid.Nil || parsedID.String() != strings.ToLower(chainID) {
		return chainID, "", errors.New("invalid chain id")
	}
	format := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "format")))
	if format != sessionExportJSON && format != sessionExportCSV {
		return chainID, format, errors.New("invalid export format")
	}
	if r.URL.RawQuery != "" {
		return chainID, format, errors.New("export does not accept query parameters")
	}
	return chainID, format, nil
}

func sessionExportErrorResponse(err error) (int, string, string) {
	switch {
	case errors.Is(err, errSessionExportNotFound):
		return http.StatusNotFound, "Configuration change session not found", "not_found"
	case errors.Is(err, errSessionExportRowLimit), errors.Is(err, errSessionExportByteLimit):
		return http.StatusRequestEntityTooLarge,
			"ConfTail export exceeds a safety limit; no partial file was returned.", "limit"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout,
			"ConfTail export was cancelled; no partial file was returned.", "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout,
			"ConfTail export timed out; no partial file was returned.", "timeout"
	default:
		return http.StatusInternalServerError,
			"Stored session data cannot be exported safely; no partial file was returned.", "error"
	}
}

func (e *Extension) buildSessionExport(
	ctx context.Context,
	chainID string,
	format string,
	limits sessionExportLimits,
) (*sessionExportBuffer, sessionExportStats, error) {
	limits = limits.normalized()
	if err := ctx.Err(); err != nil {
		return nil, sessionExportStats{}, err
	}
	tx, err := e.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, sessionExportStats{}, fmt.Errorf("begin conftail export snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	chain, count, err := loadSessionExportMetadata(ctx, tx, chainID)
	if err != nil {
		return nil, sessionExportStats{}, err
	}
	if count > limits.MaxRows {
		return nil, sessionExportStats{}, errSessionExportRowLimit
	}
	metadata, err := makeSessionExportMetadata(chain, count)
	if err != nil {
		return nil, sessionExportStats{}, err
	}
	buffer := &sessionExportBuffer{maxBytes: limits.MaxBytes}
	stats := sessionExportStats{}
	if format == sessionExportJSON {
		err = writeSessionExportJSON(ctx, tx, buffer, chainID, metadata, limits.PageSize, &stats)
	} else {
		err = writeSessionExportCSV(ctx, tx, buffer, chainID, metadata, limits.PageSize, &stats)
	}
	stats.Bytes = buffer.Len()
	if err != nil {
		return nil, stats, err
	}
	if stats.Rows != count {
		return nil, stats, fmt.Errorf("%w: event count changed inside snapshot", errSessionExportUnsafe)
	}
	return buffer, stats, nil
}

func loadSessionExportMetadata(ctx context.Context, tx *sql.Tx, chainID string) (dashboardChain, int, error) {
	chain, err := scanDashboardChain(tx.QueryRowContext(
		ctx,
		dashboardChainSelectSQL+` WHERE c.id = ?`,
		chainID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return dashboardChain{}, 0, errSessionExportNotFound
	}
	if err != nil {
		return dashboardChain{}, 0, fmt.Errorf("%w: read session metadata: %v", errSessionExportUnsafe, err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE chain_id = ?`, chainID).Scan(&count); err != nil {
		return dashboardChain{}, 0, fmt.Errorf("count conftail export events: %w", err)
	}
	return chain, count, nil
}

func makeSessionExportMetadata(chain dashboardChain, count int) (sessionExportMetadata, error) {
	if chain.ID == "" || chain.FirewallID <= 0 || chain.FirstEventAt.IsZero() || chain.LastEventAt.IsZero() ||
		chain.FirstEventAt.UnixNano() <= 0 || chain.LastEventAt.UnixNano() <= 0 ||
		chain.EventCount < 0 || count < 0 {
		return sessionExportMetadata{}, fmt.Errorf("%w: invalid session metadata", errSessionExportUnsafe)
	}
	return sessionExportMetadata{
		ID:              chain.ID,
		FirewallID:      chain.FirewallID,
		FirewallName:    exportText(chain.FirewallName, maxIdentityRunes),
		Administrator:   exportText(chain.User, maxIdentityRunes),
		StartedAt:       chain.FirstEventAt.UTC().Format(time.RFC3339Nano),
		EndedAt:         chain.LastEventAt.UTC().Format(time.RFC3339Nano),
		State:           exportText(chain.State, maxIdentityRunes),
		DeliveryState:   exportText(chain.DeliveryState, maxIdentityRunes),
		TicketRequestID: exportText(chain.RequestID, maxIdentityRunes),
		ChangeCount:     chain.EventCount,
		ExportedCount:   count,
		Late:            chain.Late,
		Unattributed:    chain.Unattributed,
	}, nil
}

func writeSessionExportJSON(
	ctx context.Context,
	tx *sql.Tx,
	w io.Writer,
	chainID string,
	metadata sessionExportMetadata,
	pageSize int,
	stats *sessionExportStats,
) error {
	header, err := json.Marshal(sessionExportDocument{SchemaVersion: sessionExportSchemaVersion, Session: metadata})
	if err != nil {
		return fmt.Errorf("encode conftail export metadata: %w", err)
	}
	if len(header) == 0 || header[len(header)-1] != '}' {
		return fmt.Errorf("%w: invalid export metadata encoding", errSessionExportUnsafe)
	}
	if _, err := w.Write(header[:len(header)-1]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `,"events":[`); err != nil {
		return err
	}
	first := true
	err = walkSessionExportEvents(ctx, tx, chainID, pageSize, stats, func(event sessionExportEvent) error {
		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		first = false
		encoded, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("encode conftail export event: %w", err)
		}
		_, err = w.Write(encoded)
		return err
	})
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, "]}")
	return err
}

func writeSessionExportCSV(
	ctx context.Context,
	tx *sql.Tx,
	w io.Writer,
	chainID string,
	metadata sessionExportMetadata,
	pageSize int,
	stats *sessionExportStats,
) error {
	writer := csv.NewWriter(w)
	writer.UseCRLF = true
	if err := writer.Write(sessionExportCSVHeader); err != nil {
		return err
	}
	err := walkSessionExportEvents(ctx, tx, chainID, pageSize, stats, func(event sessionExportEvent) error {
		record := []string{
			strconv.Itoa(event.Sequence), strconv.FormatInt(event.EventID, 10), event.EventAt,
			strconv.Itoa(metadata.FirewallID), metadata.FirewallName, metadata.Administrator,
			event.Source, event.DeviceName, event.Serial, event.VDOM, event.Attribution,
			event.UI, event.Action, event.TransactionID, event.Path, event.Object,
			event.ConfigAttribute, event.LogID, event.Description, event.Message,
			strconv.FormatBool(event.Late),
		}
		for index := range record {
			record[index] = safeCSVCell(record[index])
		}
		return writer.Write(record)
	})
	writer.Flush()
	if err != nil {
		return err
	}
	if err := writer.Error(); err != nil {
		return err
	}
	return nil
}

func walkSessionExportEvents(
	ctx context.Context,
	tx *sql.Tx,
	chainID string,
	pageSize int,
	stats *sessionExportStats,
	consume func(sessionExportEvent) error,
) error {
	lastAt, lastID := int64(math.MinInt64), int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT
			id, event_at_ns, source, device_name, device_id, vdom, user_attribution,
			ui, action, transaction_id, config_path, config_object, config_attribute,
			log_id, log_description, message, late
			FROM events
			WHERE chain_id = ? AND (event_at_ns > ? OR (event_at_ns = ? AND id > ?))
			ORDER BY event_at_ns, id LIMIT ?`,
			chainID, lastAt, lastAt, lastID, pageSize,
		)
		if err != nil {
			return fmt.Errorf("query conftail export events: %w", err)
		}
		pageRows := 0
		for rows.Next() {
			if pageRows == 0 {
				stats.Pages++
			}
			event, eventAt, scanErr := scanSessionExportEvent(rows, stats.Rows+1)
			if scanErr != nil {
				_ = rows.Close()
				return scanErr
			}
			if eventAt < lastAt || (eventAt == lastAt && event.EventID <= lastID) {
				_ = rows.Close()
				return fmt.Errorf("%w: unstable event order", errSessionExportUnsafe)
			}
			if err := consume(event); err != nil {
				_ = rows.Close()
				return err
			}
			lastAt, lastID = eventAt, event.EventID
			stats.Rows++
			pageRows++
		}
		rowsErr := rows.Err()
		_ = rows.Close()
		if rowsErr != nil {
			return fmt.Errorf("iterate conftail export events: %w", rowsErr)
		}
		if pageRows == 0 {
			return nil
		}
		if pageRows < pageSize {
			return nil
		}
	}
}

func scanSessionExportEvent(scanner dashboardScanner, sequence int) (sessionExportEvent, int64, error) {
	var event sessionExportEvent
	var eventAt int64
	var late int
	if err := scanner.Scan(
		&event.EventID, &eventAt, &event.Source, &event.DeviceName, &event.Serial,
		&event.VDOM, &event.Attribution, &event.UI, &event.Action, &event.TransactionID,
		&event.Path, &event.Object, &event.ConfigAttribute, &event.LogID,
		&event.Description, &event.Message, &late,
	); err != nil {
		return sessionExportEvent{}, 0, fmt.Errorf("%w: scan event: %v", errSessionExportUnsafe, err)
	}
	if event.EventID <= 0 || eventAt <= 0 || (late != 0 && late != 1) {
		return sessionExportEvent{}, 0, fmt.Errorf("%w: invalid event metadata", errSessionExportUnsafe)
	}
	event.Sequence = sequence
	event.EventAt = time.Unix(0, eventAt).UTC().Format(time.RFC3339Nano)
	event.Source = exportText(event.Source, maxIdentityRunes)
	event.DeviceName = exportText(event.DeviceName, maxIdentityRunes)
	event.Serial = exportText(event.Serial, maxIdentityRunes)
	event.VDOM = exportText(event.VDOM, maxIdentityRunes)
	event.Attribution = exportText(event.Attribution, maxIdentityRunes)
	event.UI = exportText(event.UI, maxIdentityRunes)
	event.Action = exportText(event.Action, maxIdentityRunes)
	event.TransactionID = exportText(event.TransactionID, maxIdentityRunes)
	event.Path = exportText(event.Path, maxDetailRunes)
	event.Object = exportText(event.Object, maxDetailRunes)
	event.ConfigAttribute = redactAttribute(truncateString(event.ConfigAttribute, maxDetailRunes))
	event.LogID = exportText(event.LogID, maxIdentityRunes)
	event.Description = redactFreeText(truncateString(event.Description, maxDetailRunes))
	event.Message = redactFreeText(truncateString(event.Message, maxDetailRunes))
	event.Late = late == 1
	return event, eventAt, nil
}

func exportText(value string, maxRunes int) string {
	return sanitizeExternalString(strings.ToValidUTF8(value, "�"), maxRunes)
}

func safeCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func (e *Extension) recordSessionExport(
	r *http.Request,
	chainID string,
	format string,
	stats sessionExportStats,
	outcome string,
	startedAt time.Time,
) {
	duration := time.Since(startedAt).Milliseconds()
	actor := ""
	if e.currentUser != nil {
		actor = sanitizeExternalString(e.currentUser(r), maxIdentityRunes)
	}
	if e.logger != nil {
		e.logger.InfoContext(r.Context(), "conftail session export",
			"code", codeSessionExported,
			"actor", actor,
			"session_id", chainID,
			"format", format,
			"pages", stats.Pages,
			"rows", stats.Rows,
			"bytes", stats.Bytes,
			"duration_ms", duration,
			"outcome", outcome,
			"reqid", middleware.GetReqID(r.Context()),
		)
	}
	if e.logActivity != nil {
		e.logActivity(actor, "ConfTail Session Export", fmt.Sprintf(
			"session_id=%s format=%s pages=%d rows=%d bytes=%d duration_ms=%d outcome=%s",
			chainID, format, stats.Pages, stats.Rows, stats.Bytes, duration, outcome,
		))
	}
}
