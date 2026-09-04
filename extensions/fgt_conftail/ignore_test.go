package fgtconftail

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/config"
)

func TestGlobalAttributeIgnoreSuppressesFutureMatchesWithoutDeletingHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	store := newTestStore(t, base)
	first := testEvent(1, "fw-a", "alice", "attribute-first", base.Add(time.Minute))
	first.ConfigAttribute = `type[fortimanager->fortimanager]fmg["manager.example.test"->"manager.example.test"]serial-number["FMGVMTEST00000001"->"FMGVMTEST00000001"]`
	first.SemanticHash = semanticHash(first)
	if _, err := store.applyPoll(ctx, pollBatch{EndedAt: base.Add(2 * time.Minute), Events: []Event{first}}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	eventID := storedEventID(t, store, first.GraylogID)
	rule, created, err := store.createGlobalIgnoreRule(ctx, eventID, ignoreRuleKindAttribute, "operator", base.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !created || !rule.Enabled || rule.ConfigAttribute != first.ConfigAttribute || rule.CreatedBy != "operator" {
		t.Fatalf("created attribute rule = %+v, created=%t", rule, created)
	}

	repeated := first
	repeated.GraylogID = "attribute-repeated"
	repeated.EventAt = base.Add(4 * time.Minute)
	repeated.IngestedAt = repeated.EventAt.Add(time.Minute)
	repeated.SemanticHash = semanticHash(repeated)
	result, err := store.applyPoll(ctx, pollBatch{EndedAt: base.Add(6 * time.Minute), Events: []Event{repeated}}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result.Ignored != 1 || result.Inserted != 0 || countRows(t, store, "events") != 1 || countRows(t, store, "ignored_events") != 1 {
		t.Fatalf("ignored poll result = %+v, events=%d ignored_events=%d", result, countRows(t, store, "events"), countRows(t, store, "ignored_events"))
	}

	rules, err := store.listGlobalIgnoreRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].ID != rule.ID {
		t.Fatalf("listed rules = %+v, err=%v", rules, err)
	}
	if err := store.setGlobalIgnoreRuleEnabled(ctx, rule.ID, false); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.applyPoll(ctx, pollBatch{EndedAt: base.Add(7 * time.Minute), Events: []Event{repeated}}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil || replayed.Duplicates != 1 || replayed.Inserted != 0 {
		t.Fatalf("previously ignored event re-entered after disabling rule: result=%+v err=%v", replayed, err)
	}
	afterDisable := repeated
	afterDisable.GraylogID = "attribute-after-disable"
	afterDisable.EventAt = base.Add(8 * time.Minute)
	afterDisable.IngestedAt = afterDisable.EventAt.Add(time.Minute)
	afterDisable.SemanticHash = semanticHash(afterDisable)
	result, err = store.applyPoll(ctx, pollBatch{EndedAt: base.Add(9 * time.Minute), Events: []Event{afterDisable}}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil || result.Inserted != 1 {
		t.Fatalf("disabled rule still ignored event: result=%+v err=%v", result, err)
	}
	if err := store.deleteGlobalIgnoreRule(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, store, "global_ignore_rules"); got != 0 {
		t.Fatalf("rules after delete = %d", got)
	}
	if _, err := store.prune(ctx, base.Add(40*24*time.Hour), 30); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, store, "ignored_events"); got != 0 {
		t.Fatalf("ignored event identities after retention prune = %d", got)
	}
}

func TestGlobalOperationIgnoreMatchesActionAndPathAcrossAttributes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	store := newTestStore(t, base)
	first := testEvent(1, "fw-a", "alice", "operation-first", base.Add(time.Minute))
	first.Path = "system.central-management"
	first.ConfigAttribute = "server[old->new]"
	first.SemanticHash = semanticHash(first)
	if _, err := store.applyPoll(ctx, pollBatch{EndedAt: base.Add(2 * time.Minute), Events: []Event{first}}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	rule, _, err := store.createGlobalIgnoreRule(ctx, storedEventID(t, store, first.GraylogID), ignoreRuleKindOperation, "operator", base.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rule.Action != "Edit" || rule.Path != "system.central-management" || rule.DisplayValue() != "Edit system.central-management" {
		t.Fatalf("operation rule = %+v", rule)
	}

	repeated := first
	repeated.GraylogID = "operation-repeated"
	repeated.ConfigAttribute = "fmg[source-a->source-b]"
	repeated.EventAt = base.Add(4 * time.Minute)
	repeated.IngestedAt = repeated.EventAt.Add(time.Minute)
	repeated.SemanticHash = semanticHash(repeated)
	result, err := store.applyPoll(ctx, pollBatch{EndedAt: base.Add(5 * time.Minute), Events: []Event{repeated}}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil || result.Ignored != 1 {
		t.Fatalf("operation match result=%+v err=%v", result, err)
	}

	differentPath := repeated
	differentPath.GraylogID = "operation-different-path"
	differentPath.Path = "system.dns"
	differentPath.EventAt = base.Add(6 * time.Minute)
	differentPath.IngestedAt = differentPath.EventAt.Add(time.Minute)
	differentPath.SemanticHash = semanticHash(differentPath)
	result, err = store.applyPoll(ctx, pollBatch{EndedAt: base.Add(7 * time.Minute), Events: []Event{differentPath}}, 30*time.Minute, maxTicketDescriptionBytes)
	if err != nil || result.Inserted != 1 {
		t.Fatalf("operation rule overmatched: result=%+v err=%v", result, err)
	}
}

func TestGlobalIgnoreHandlersRequireStoredEventAndAuditMutations(t *testing.T) {
	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, base)
	event := testEvent(1, "fw-a", "alice", "handler-event", base.Add(time.Minute))
	event.ConfigAttribute = "private-sentinel[before->after]"
	event.SemanticHash = semanticHash(event)
	if _, err := store.applyPoll(context.Background(), pollBatch{EndedAt: base.Add(2 * time.Minute), Events: []Event{event}}, 30*time.Minute, maxTicketDescriptionBytes); err != nil {
		t.Fatal(err)
	}
	eventID := storedEventID(t, store, event.GraylogID)
	var activities []string
	var logs bytes.Buffer
	extension := &Extension{
		cfg: &config.Config{ExtFgtConfTail: true}, store: store,
		logger:      slog.New(slog.NewJSONHandler(&logs, nil)),
		currentUser: func(*http.Request) string { return "operator" },
		logActivity: func(username, action, details string) {
			activities = append(activities, strings.Join([]string{username, action, details}, "|"))
		},
	}
	router := chi.NewRouter()
	router.Post("/ignore-rules", extension.createGlobalIgnoreRule)
	router.Post("/ignore-rules/{ruleID}/toggle", extension.toggleGlobalIgnoreRule)
	router.Post("/ignore-rules/{ruleID}/delete", extension.deleteGlobalIgnoreRule)

	postForm := func(path string, values url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	created := postForm("/ignore-rules", url.Values{"event_id": {strconv.FormatInt(eventID, 10)}, "kind": {ignoreRuleKindAttribute}})
	if created.Code != http.StatusSeeOther || created.Header().Get("Location") == "" {
		t.Fatalf("create response = %d location=%q body=%q", created.Code, created.Header().Get("Location"), created.Body.String())
	}
	rules, err := store.listGlobalIgnoreRules(context.Background())
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	ruleID := strconv.FormatInt(rules[0].ID, 10)
	if response := postForm("/ignore-rules/"+ruleID+"/toggle", url.Values{"enabled": {"false"}}); response.Code != http.StatusSeeOther {
		t.Fatalf("toggle response = %d", response.Code)
	}
	if response := postForm("/ignore-rules/"+ruleID+"/delete", nil); response.Code != http.StatusSeeOther {
		t.Fatalf("delete response = %d", response.Code)
	}
	if len(activities) != 3 || !strings.Contains(strings.Join(activities, "\n"), "ConfTail Global Ignore") {
		t.Fatalf("activities = %#v", activities)
	}
	for _, want := range []string{`"msg":"conftail global ignore created"`, `"actor":"operator"`, `"rule_id":`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("application log missing %q: %s", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), "private-sentinel") || strings.Contains(strings.Join(activities, "\n"), "private-sentinel") {
		t.Fatalf("global ignore audit logs contain the exact match value: logs=%q activities=%#v", logs.String(), activities)
	}
	invalid := postForm("/ignore-rules", url.Values{"event_id": {"999999"}, "kind": {ignoreRuleKindAttribute}})
	if invalid.Code != http.StatusNotFound {
		t.Fatalf("missing event response = %d, want 404", invalid.Code)
	}
	for _, want := range []string{`"msg":"conftail global ignore mutation failed"`, `"operation":"create"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("failed mutation log missing %q: %s", want, logs.String())
		}
	}
}

func storedEventID(t *testing.T, store *store, graylogID string) int64 {
	t.Helper()
	var id int64
	if err := store.db.QueryRow(`SELECT id FROM events WHERE graylog_id = ?`, graylogID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
