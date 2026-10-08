package fgtconftail

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	ignoreRuleKindAttribute = "attribute"
	ignoreRuleKindOperation = "operation"
)

var (
	errGlobalIgnoreEventNotFound = errors.New("conftail ignore source event not found")
	errGlobalIgnoreRuleNotFound  = errors.New("conftail global ignore rule not found")
)

type globalIgnoreRule struct {
	ID              int64
	Kind            string
	Action          string
	Path            string
	ConfigAttribute string
	Enabled         bool
	CreatedBy       string
	CreatedAt       time.Time
	SourceChainID   string
}

func (rule globalIgnoreRule) DisplayValue() string {
	if rule.Kind == ignoreRuleKindOperation {
		return strings.TrimSpace(rule.Action + " " + rule.Path)
	}
	return rule.ConfigAttribute
}

func (rule globalIgnoreRule) matches(event Event) bool {
	switch rule.Kind {
	case ignoreRuleKindAttribute:
		return rule.ConfigAttribute != "" && rule.ConfigAttribute == event.ConfigAttribute
	case ignoreRuleKindOperation:
		return rule.Action != "" && rule.Path != "" && rule.Action == event.Action && rule.Path == event.Path
	default:
		return false
	}
}

func matchingGlobalIgnoreRule(rules []globalIgnoreRule, event Event) (globalIgnoreRule, bool) {
	for _, rule := range rules {
		if rule.Enabled && rule.matches(event) {
			return rule, true
		}
	}
	return globalIgnoreRule{}, false
}

func scanGlobalIgnoreRule(scanner interface{ Scan(...any) error }) (globalIgnoreRule, error) {
	var rule globalIgnoreRule
	var enabled int
	var createdAt int64
	err := scanner.Scan(&rule.ID, &rule.Kind, &rule.Action, &rule.Path, &rule.ConfigAttribute, &enabled, &rule.CreatedBy, &createdAt)
	if err != nil {
		return globalIgnoreRule{}, err
	}
	rule.Enabled = enabled != 0
	rule.CreatedAt = timeFromNanos(createdAt)
	return rule, nil
}

const globalIgnoreRuleColumns = `id, kind, action, config_path, config_attribute, enabled, created_by, created_at_ns`

func listEnabledGlobalIgnoreRulesTx(ctx context.Context, tx *sql.Tx) ([]globalIgnoreRule, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+globalIgnoreRuleColumns+` FROM global_ignore_rules WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list enabled conftail global ignore rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var rules []globalIgnoreRule
	for rows.Next() {
		rule, scanErr := scanGlobalIgnoreRule(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan enabled conftail global ignore rule: %w", scanErr)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enabled conftail global ignore rules: %w", err)
	}
	return rules, nil
}

func (s *store) listGlobalIgnoreRules(ctx context.Context) ([]globalIgnoreRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+globalIgnoreRuleColumns+` FROM global_ignore_rules ORDER BY enabled DESC, created_at_ns DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list conftail global ignore rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var rules []globalIgnoreRule
	for rows.Next() {
		rule, scanErr := scanGlobalIgnoreRule(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan conftail global ignore rule: %w", scanErr)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate conftail global ignore rules: %w", err)
	}
	return rules, nil
}

func (s *store) createGlobalIgnoreRule(ctx context.Context, eventID int64, kind, actor string, now time.Time) (globalIgnoreRule, bool, error) {
	if eventID <= 0 || (kind != ignoreRuleKindAttribute && kind != ignoreRuleKindOperation) {
		return globalIgnoreRule{}, false, errors.New("invalid conftail global ignore request")
	}
	if !unixNanoRepresentable(now) {
		return globalIgnoreRule{}, false, errors.New("invalid conftail global ignore timestamp")
	}
	actor = sanitizeExternalString(actor, maxIdentityRunes)
	if actor == "" {
		actor = "[unknown]"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return globalIgnoreRule{}, false, fmt.Errorf("begin conftail global ignore transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var chainID, action, path, attribute string
	err = tx.QueryRowContext(ctx, `SELECT chain_id, action, config_path, config_attribute FROM events WHERE id = ?`, eventID).
		Scan(&chainID, &action, &path, &attribute)
	if errors.Is(err, sql.ErrNoRows) {
		return globalIgnoreRule{}, false, errGlobalIgnoreEventNotFound
	}
	if err != nil {
		return globalIgnoreRule{}, false, fmt.Errorf("read conftail ignore source event: %w", err)
	}
	if kind == ignoreRuleKindAttribute {
		action, path = "", ""
		if attribute == "" {
			return globalIgnoreRule{}, false, errors.New("conftail event has no attribute ignore candidate")
		}
	} else {
		attribute = ""
		if action == "" || path == "" {
			return globalIgnoreRule{}, false, errors.New("conftail event has no operation ignore candidate")
		}
	}
	query := `SELECT ` + globalIgnoreRuleColumns + ` FROM global_ignore_rules
		WHERE kind = ? AND action = ? AND config_path = ? AND config_attribute = ?`
	rule, err := scanGlobalIgnoreRule(tx.QueryRowContext(ctx, query, kind, action, path, attribute))
	created := false
	if errors.Is(err, sql.ErrNoRows) {
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO global_ignore_rules
			(kind, action, config_path, config_attribute, enabled, created_by, created_at_ns)
			VALUES (?, ?, ?, ?, 1, ?, ?)`, kind, action, path, attribute, actor, unixNanos(now))
		if insertErr != nil {
			return globalIgnoreRule{}, false, fmt.Errorf("create conftail global ignore rule: %w", insertErr)
		}
		id, idErr := result.LastInsertId()
		if idErr != nil {
			return globalIgnoreRule{}, false, fmt.Errorf("read conftail global ignore rule id: %w", idErr)
		}
		rule, err = scanGlobalIgnoreRule(tx.QueryRowContext(ctx, `SELECT `+globalIgnoreRuleColumns+` FROM global_ignore_rules WHERE id = ?`, id))
		created = true
	}
	if err != nil {
		return globalIgnoreRule{}, false, fmt.Errorf("read conftail global ignore rule: %w", err)
	}
	if !rule.Enabled {
		if _, err := tx.ExecContext(ctx, `UPDATE global_ignore_rules SET enabled = 1 WHERE id = ?`, rule.ID); err != nil {
			return globalIgnoreRule{}, false, fmt.Errorf("reactivate conftail global ignore rule: %w", err)
		}
		rule.Enabled = true
	}
	rule.SourceChainID = chainID
	if err := tx.Commit(); err != nil {
		return globalIgnoreRule{}, false, fmt.Errorf("commit conftail global ignore rule: %w", err)
	}
	return rule, created, nil
}

func (s *store) setGlobalIgnoreRuleEnabled(ctx context.Context, ruleID int64, enabled bool) error {
	if ruleID <= 0 {
		return errors.New("invalid conftail global ignore rule id")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE global_ignore_rules SET enabled = ? WHERE id = ?`, boolInt(enabled), ruleID)
	if err != nil {
		return fmt.Errorf("toggle conftail global ignore rule: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect conftail global ignore toggle: %w", err)
	}
	if changed == 0 {
		return errGlobalIgnoreRuleNotFound
	}
	return nil
}

func (s *store) deleteGlobalIgnoreRule(ctx context.Context, ruleID int64) error {
	if ruleID <= 0 {
		return errors.New("invalid conftail global ignore rule id")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM global_ignore_rules WHERE id = ?`, ruleID)
	if err != nil {
		return fmt.Errorf("delete conftail global ignore rule: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect conftail global ignore deletion: %w", err)
	}
	if changed == 0 {
		return errGlobalIgnoreRuleNotFound
	}
	return nil
}

func recordIgnoredEvent(ctx context.Context, tx *sql.Tx, ruleID int64, event Event, ignoredAt time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ignored_events
		(semantic_hash, graylog_id, rule_id, event_at_ns, ignored_at_ns) VALUES (?, ?, ?, ?, ?)`,
		event.SemanticHash, event.GraylogID, ruleID, unixNanos(event.EventAt), unixNanos(ignoredAt))
	if err != nil {
		return false, fmt.Errorf("record conftail ignored event: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect conftail ignored event: %w", err)
	}
	return changed > 0, nil
}

func (e *Extension) createGlobalIgnoreRule(w http.ResponseWriter, r *http.Request) {
	if e.store == nil {
		http.Error(w, "Configuration change ignore rules unavailable", http.StatusServiceUnavailable)
		return
	}
	actor := e.requestActor(r)
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		e.logIgnoreFailure(r, "create", actor, 0, errors.New("invalid form body"))
		http.Error(w, "Invalid global ignore request", http.StatusBadRequest)
		return
	}
	eventID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("event_id")), 10, 64)
	if err != nil || eventID <= 0 {
		e.logIgnoreFailure(r, "create", actor, 0, errors.New("invalid event id"))
		http.Error(w, "Invalid global ignore event", http.StatusBadRequest)
		return
	}
	kind := strings.TrimSpace(r.FormValue("kind"))
	rule, created, err := e.store.createGlobalIgnoreRule(r.Context(), eventID, kind, actor, time.Now().UTC())
	if errors.Is(err, errGlobalIgnoreEventNotFound) {
		e.logIgnoreFailure(r, "create", actor, 0, err)
		http.Error(w, "Configuration change event not found", http.StatusNotFound)
		return
	}
	if err != nil {
		e.logIgnoreFailure(r, "create", actor, 0, err)
		http.Error(w, "Unable to create global ignore rule", http.StatusBadRequest)
		return
	}
	if e.logger != nil {
		e.logger.InfoContext(r.Context(), "conftail global ignore created",
			"code", codeGlobalIgnoreChanged, "actor", actor, "rule_id", rule.ID,
			"kind", rule.Kind, "created", created, "reqid", middleware.GetReqID(r.Context()))
	}
	if e.logActivity != nil {
		e.logActivity(actor, "ConfTail Global Ignore Created",
			fmt.Sprintf("rule_id=%d kind=%s created=%t", rule.ID, rule.Kind, created))
	}
	location := "/fgt-conftail/"
	if rule.SourceChainID != "" {
		location = "/fgt-conftail/chain/" + url.PathEscape(rule.SourceChainID) + "?ignore=created"
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func (e *Extension) toggleGlobalIgnoreRule(w http.ResponseWriter, r *http.Request) {
	if e.store == nil {
		http.Error(w, "Configuration change ignore rules unavailable", http.StatusServiceUnavailable)
		return
	}
	ruleID, ok := parseIgnoreRuleID(w, r)
	if !ok {
		return
	}
	enabled, err := strconv.ParseBool(strings.TrimSpace(r.FormValue("enabled")))
	if err != nil {
		http.Error(w, "Invalid global ignore state", http.StatusBadRequest)
		return
	}
	actor := e.requestActor(r)
	if err := e.store.setGlobalIgnoreRuleEnabled(r.Context(), ruleID, enabled); err != nil {
		e.handleIgnoreMutationError(w, r, "toggle", actor, ruleID, err)
		return
	}
	e.logIgnoreMutation(r, actor, "toggled", ruleID, fmt.Sprintf("enabled=%t", enabled))
	http.Redirect(w, r, "/fgt-conftail/?ignore=updated#ct-global-ignores", http.StatusSeeOther)
}

func (e *Extension) deleteGlobalIgnoreRule(w http.ResponseWriter, r *http.Request) {
	if e.store == nil {
		http.Error(w, "Configuration change ignore rules unavailable", http.StatusServiceUnavailable)
		return
	}
	ruleID, ok := parseIgnoreRuleID(w, r)
	if !ok {
		return
	}
	actor := e.requestActor(r)
	if err := e.store.deleteGlobalIgnoreRule(r.Context(), ruleID); err != nil {
		e.handleIgnoreMutationError(w, r, "delete", actor, ruleID, err)
		return
	}
	e.logIgnoreMutation(r, actor, "deleted", ruleID, "")
	http.Redirect(w, r, "/fgt-conftail/?ignore=deleted#ct-global-ignores", http.StatusSeeOther)
}

func parseIgnoreRuleID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	ruleID, err := strconv.ParseInt(strings.TrimSpace(chi.URLParam(r, "ruleID")), 10, 64)
	if err != nil || ruleID <= 0 {
		http.Error(w, "Invalid global ignore rule", http.StatusBadRequest)
		return 0, false
	}
	return ruleID, true
}

func (e *Extension) requestActor(r *http.Request) string {
	actor := ""
	if e.currentUser != nil {
		actor = e.currentUser(r)
	}
	actor = sanitizeExternalString(actor, maxIdentityRunes)
	if actor == "" {
		return "[unknown]"
	}
	return actor
}

func (e *Extension) handleIgnoreMutationError(w http.ResponseWriter, r *http.Request, operation, actor string, ruleID int64, err error) {
	e.logIgnoreFailure(r, operation, actor, ruleID, err)
	if errors.Is(err, errGlobalIgnoreRuleNotFound) {
		http.Error(w, "Global ignore rule not found", http.StatusNotFound)
		return
	}
	http.Error(w, "Unable to update global ignore rule", http.StatusInternalServerError)
}

func (e *Extension) logIgnoreFailure(r *http.Request, operation, actor string, ruleID int64, err error) {
	if e.logger != nil {
		e.logger.ErrorContext(r.Context(), "conftail global ignore mutation failed",
			"code", codeGlobalIgnoreFailed, "actor", actor, "operation", operation,
			"rule_id", ruleID, "err", sanitizeDeliveryError(err), "reqid", middleware.GetReqID(r.Context()))
	}
}

func (e *Extension) logIgnoreMutation(r *http.Request, actor, operation string, ruleID int64, detail string) {
	if e.logger != nil {
		e.logger.InfoContext(r.Context(), "conftail global ignore "+operation,
			"code", codeGlobalIgnoreChanged, "actor", actor, "rule_id", ruleID,
			"detail", detail, "reqid", middleware.GetReqID(r.Context()))
	}
	if e.logActivity != nil {
		e.logActivity(actor, "ConfTail Global Ignore "+strings.ToUpper(operation[:1])+operation[1:],
			strings.TrimSpace(fmt.Sprintf("rule_id=%d %s", ruleID, detail)))
	}
}
