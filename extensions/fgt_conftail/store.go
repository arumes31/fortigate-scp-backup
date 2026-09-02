package fgtconftail

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

const (
	chainStateActive          = "active"
	chainStateSealed          = "sealed"
	chainStateStaging         = "staging"
	deliveryStatePending      = "pending"
	deliveryStateRetry        = "retry"
	deliveryStateFailed       = "failed"
	deliveryStateAccepted     = "accepted"
	maxTicketDescriptionBytes = 60_000
	conftailSchemaVersion     = 2
)

type store struct {
	db *sql.DB
}

type PollState struct {
	ActivationAt   time.Time
	Watermark      time.Time
	LastStartedAt  time.Time
	LastSuccessAt  time.Time
	LastFailureAt  time.Time
	LastDuration   time.Duration
	LastPages      int
	LastFetched    int
	LastInserted   int
	LastError      string
	LastIngestedAt time.Time
}

type pollBatch struct {
	StartedAt   time.Time
	EndedAt     time.Time
	CompletedAt time.Time
	Pages       int
	Fetched     int
	Events      []Event
}

type pollResult struct {
	Inserted   int
	Duplicates int
	Sealed     int
}

type chainRecord struct {
	ID           string
	FirewallID   int
	FirewallName string
	User         string
	FirstEventAt time.Time
	LastEventAt  time.Time
	EventCount   int
	State        string
	Late         bool
	Unattributed bool
	SealedAt     time.Time
}

var conftailSchema = []string{
	`CREATE TABLE IF NOT EXISTS schema_meta (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		version INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS chains (
		id TEXT PRIMARY KEY,
		firewall_id INTEGER NOT NULL,
		firewall_name TEXT NOT NULL,
		user TEXT NOT NULL,
		first_event_at_ns INTEGER NOT NULL,
		last_event_at_ns INTEGER NOT NULL,
		event_count INTEGER NOT NULL CHECK (event_count > 0),
		state TEXT NOT NULL CHECK (state IN ('active','sealed','staging')),
		late INTEGER NOT NULL DEFAULT 0 CHECK (late IN (0,1)),
		unattributed INTEGER NOT NULL DEFAULT 0 CHECK (unattributed IN (0,1)),
		sealed_at_ns INTEGER NOT NULL DEFAULT 0,
		created_at_ns INTEGER NOT NULL
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS chains_one_active_key
		ON chains(firewall_id, user) WHERE state = 'active'`,
	`CREATE INDEX IF NOT EXISTS chains_state_last_event
		ON chains(state, last_event_at_ns)`,
	`CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		graylog_id TEXT NOT NULL DEFAULT '',
		semantic_hash TEXT NOT NULL UNIQUE,
		correlation_hash TEXT NOT NULL,
		chain_id TEXT NOT NULL REFERENCES chains(id) ON DELETE CASCADE,
		firewall_id INTEGER NOT NULL,
		firewall_name TEXT NOT NULL,
		source TEXT NOT NULL,
		device_name TEXT NOT NULL DEFAULT '',
		device_id TEXT NOT NULL DEFAULT '',
		vdom TEXT NOT NULL DEFAULT '',
		user TEXT NOT NULL,
		user_attribution TEXT NOT NULL CHECK (user_attribution IN ('exact','recovered','unattributed')),
		user_was_missing INTEGER NOT NULL CHECK (user_was_missing IN (0,1)),
		ui TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT '',
		transaction_id TEXT NOT NULL DEFAULT '',
		config_path TEXT NOT NULL DEFAULT '',
		config_object TEXT NOT NULL DEFAULT '',
		config_attribute TEXT NOT NULL DEFAULT '',
		log_id TEXT NOT NULL,
		log_description TEXT NOT NULL DEFAULT '',
		message TEXT NOT NULL DEFAULT '',
		uuid TEXT NOT NULL DEFAULT '',
		event_at_ns INTEGER NOT NULL,
		ingested_at_ns INTEGER NOT NULL,
		late INTEGER NOT NULL DEFAULT 0 CHECK (late IN (0,1))
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS events_graylog_identity
		ON events(graylog_id) WHERE graylog_id != ''`,
	`CREATE INDEX IF NOT EXISTS events_missing_correlation
		ON events(correlation_hash) WHERE user_was_missing = 1`,
	`CREATE INDEX IF NOT EXISTS events_chain_timeline
		ON events(chain_id, event_at_ns, semantic_hash)`,
	`CREATE VIRTUAL TABLE IF NOT EXISTS event_search USING fts5(
		firewall_name, user, source, device_name, device_id, vdom, action,
		config_path, config_object, config_attribute, log_description, message,
		content='events', content_rowid='id', tokenize='unicode61'
	)`,
	`CREATE TRIGGER IF NOT EXISTS events_search_insert AFTER INSERT ON events BEGIN
		INSERT INTO event_search(
			rowid, firewall_name, user, source, device_name, device_id, vdom,
			action, config_path, config_object, config_attribute,
			log_description, message
		) VALUES (
			new.id, new.firewall_name, new.user, new.source, new.device_name,
			new.device_id, new.vdom, new.action, new.config_path,
			new.config_object, new.config_attribute, new.log_description, new.message
		);
	END`,
	`CREATE TRIGGER IF NOT EXISTS events_search_delete AFTER DELETE ON events BEGIN
		INSERT INTO event_search(
			event_search, rowid, firewall_name, user, source, device_name,
			device_id, vdom, action, config_path, config_object,
			config_attribute, log_description, message
		) VALUES (
			'delete', old.id, old.firewall_name, old.user, old.source,
			old.device_name, old.device_id, old.vdom, old.action, old.config_path,
			old.config_object, old.config_attribute, old.log_description, old.message
		);
	END`,
	`CREATE TRIGGER IF NOT EXISTS events_search_update AFTER UPDATE ON events BEGIN
		INSERT INTO event_search(
			event_search, rowid, firewall_name, user, source, device_name,
			device_id, vdom, action, config_path, config_object,
			config_attribute, log_description, message
		) VALUES (
			'delete', old.id, old.firewall_name, old.user, old.source,
			old.device_name, old.device_id, old.vdom, old.action, old.config_path,
			old.config_object, old.config_attribute, old.log_description, old.message
		);
		INSERT INTO event_search(
			rowid, firewall_name, user, source, device_name, device_id, vdom,
			action, config_path, config_object, config_attribute,
			log_description, message
		) VALUES (
			new.id, new.firewall_name, new.user, new.source, new.device_name,
			new.device_id, new.vdom, new.action, new.config_path,
			new.config_object, new.config_attribute, new.log_description, new.message
		);
	END`,
	`CREATE TABLE IF NOT EXISTS outbox (
		chain_id TEXT PRIMARY KEY REFERENCES chains(id) ON DELETE CASCADE,
		payload_json BLOB NOT NULL,
		state TEXT NOT NULL CHECK (state IN ('pending','retry','failed','accepted')),
		attempt_count INTEGER NOT NULL DEFAULT 0,
		next_attempt_at_ns INTEGER NOT NULL,
		last_error TEXT NOT NULL DEFAULT '',
		request_id TEXT NOT NULL DEFAULT '',
		accepted_at_ns INTEGER NOT NULL DEFAULT 0,
		updated_at_ns INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS outbox_due
		ON outbox(state, next_attempt_at_ns)`,
	`CREATE TABLE IF NOT EXISTS poll_state (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		activation_at_ns INTEGER NOT NULL,
		watermark_ns INTEGER NOT NULL,
		last_started_at_ns INTEGER NOT NULL DEFAULT 0,
		last_success_at_ns INTEGER NOT NULL DEFAULT 0,
		last_failure_at_ns INTEGER NOT NULL DEFAULT 0,
		last_duration_ns INTEGER NOT NULL DEFAULT 0,
		last_pages INTEGER NOT NULL DEFAULT 0,
		last_fetched INTEGER NOT NULL DEFAULT 0,
		last_inserted INTEGER NOT NULL DEFAULT 0,
		last_error TEXT NOT NULL DEFAULT '',
		updated_at_ns INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS managed_indexes (
		name TEXT PRIMARY KEY,
		created_at_ns INTEGER NOT NULL,
		last_needed_at_ns INTEGER NOT NULL
	)`,
}

func unixNanos(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UTC().UnixNano()
}

func timeFromNanos(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

func openStore(ctx context.Context, path string, activation time.Time) (*store, error) {
	dataDir := filepath.Dir(path)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create conftail data directory: %w", err)
	}
	if dataDir != "." {
		if err := os.Chmod(dataDir, 0o700); err != nil {
			return nil, fmt.Errorf("protect conftail data directory: %w", err)
		}
	}
	dsn, err := conftailSQLiteDSN(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open conftail database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	closeOnError := func(err error) (*store, error) {
		_ = db.Close()
		return nil, err
	}
	for _, statement := range []string{
		"PRAGMA auto_vacuum=INCREMENTAL",
		"PRAGMA journal_mode=WAL",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return closeOnError(fmt.Errorf("initialize conftail database: %w", err))
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return closeOnError(fmt.Errorf("protect conftail database: %w", err))
	}
	s := &store{db: db}
	if err := s.initSchema(ctx, activation.UTC()); err != nil {
		return closeOnError(err)
	}
	return s, nil
}

func conftailSQLiteDSN(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve conftail database path: %w", err)
	}
	urlPath := filepath.ToSlash(absolutePath)
	if filepath.VolumeName(absolutePath) != "" && !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}
	databaseURL := url.URL{Scheme: "file", Path: urlPath}
	query := databaseURL.Query()
	// modernc applies every _pragma value whenever it creates an underlying
	// connection. These settings must not depend on database/sql retaining the
	// connection that initialized the schema.
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "synchronous(NORMAL)")
	query.Add("_pragma", "foreign_keys(1)")
	databaseURL.RawQuery = query.Encode()
	return databaseURL.String(), nil
}

func (s *store) close() error {
	return s.db.Close()
}

func (s *store) initSchema(ctx context.Context, activation time.Time) error {
	if !unixNanoRepresentable(activation) {
		return errors.New("conftail activation timestamp is outside the supported range")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin conftail schema transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range conftailSchema {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize conftail schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_meta (id, version) VALUES (1, ?)
		 ON CONFLICT(id) DO NOTHING`, conftailSchemaVersion); err != nil {
		return fmt.Errorf("initialize conftail schema version: %w", err)
	}
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT version FROM schema_meta WHERE id = 1`).Scan(&version); err != nil {
		return fmt.Errorf("read conftail schema version: %w", err)
	}
	if version == 1 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO event_search(event_search) VALUES('rebuild')`); err != nil {
			return fmt.Errorf("rebuild conftail event search index: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE schema_meta SET version = ? WHERE id = 1`, conftailSchemaVersion); err != nil {
			return fmt.Errorf("upgrade conftail schema version: %w", err)
		}
		version = conftailSchemaVersion
	}
	if version != conftailSchemaVersion {
		return fmt.Errorf("unsupported conftail schema version %d", version)
	}
	activationNanos := unixNanos(activation)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO poll_state (id, activation_at_ns, watermark_ns, updated_at_ns)
		 VALUES (1, ?, ?, ?)
		 ON CONFLICT(id) DO NOTHING`, activationNanos, activationNanos, activationNanos); err != nil {
		return fmt.Errorf("initialize conftail poll state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit conftail schema: %w", err)
	}
	return nil
}

func (s *store) pollState(ctx context.Context) (PollState, error) {
	var activation, watermark, started, success, failure, duration, lastIngested int64
	var state PollState
	err := s.db.QueryRowContext(ctx, `SELECT
		activation_at_ns, watermark_ns, last_started_at_ns, last_success_at_ns,
		last_failure_at_ns, last_duration_ns, last_pages, last_fetched,
		last_inserted, last_error,
		(SELECT COALESCE(MAX(ingested_at_ns), 0) FROM events)
		FROM poll_state WHERE id = 1`).Scan(
		&activation,
		&watermark,
		&started,
		&success,
		&failure,
		&duration,
		&state.LastPages,
		&state.LastFetched,
		&state.LastInserted,
		&state.LastError,
		&lastIngested,
	)
	if err != nil {
		return PollState{}, fmt.Errorf("read conftail poll state: %w", err)
	}
	state.ActivationAt = timeFromNanos(activation)
	state.Watermark = timeFromNanos(watermark)
	state.LastStartedAt = timeFromNanos(started)
	state.LastSuccessAt = timeFromNanos(success)
	state.LastFailureAt = timeFromNanos(failure)
	state.LastDuration = time.Duration(duration) * time.Nanosecond
	state.LastIngestedAt = timeFromNanos(lastIngested)
	return state, nil
}

func (s *store) pollScheduleState(ctx context.Context) (PollState, time.Time, error) {
	state, err := s.pollState(ctx)
	if err != nil {
		return PollState{}, time.Time{}, err
	}
	return state, state.LastIngestedAt, nil
}

func (s *store) markPollStarted(ctx context.Context, startedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE poll_state SET
		last_started_at_ns = ?, last_error = '', updated_at_ns = ? WHERE id = 1`,
		unixNanos(startedAt), unixNanos(startedAt))
	if err != nil {
		return fmt.Errorf("mark conftail poll started: %w", err)
	}
	return nil
}

func (s *store) markPollFailed(
	ctx context.Context,
	startedAt time.Time,
	failedAt time.Time,
	pollErr error,
) error {
	duration := failedAt.Sub(startedAt)
	if duration < 0 {
		duration = 0
	}
	_, err := s.db.ExecContext(ctx, `UPDATE poll_state SET
		last_failure_at_ns = ?, last_duration_ns = ?, last_error = ?, updated_at_ns = ?
		WHERE id = 1`,
		unixNanos(failedAt),
		duration.Nanoseconds(),
		sanitizeDeliveryError(pollErr),
		unixNanos(failedAt),
	)
	if err != nil {
		return fmt.Errorf("mark conftail poll failed: %w", err)
	}
	return nil
}

func (s *store) applyPoll(
	ctx context.Context,
	batch pollBatch,
	idle time.Duration,
	maxDescriptionBytes int,
) (pollResult, error) {
	if batch.EndedAt.IsZero() {
		return pollResult{}, errors.New("conftail poll end is required")
	}
	if !unixNanoRepresentable(batch.EndedAt) ||
		(!batch.StartedAt.IsZero() && !unixNanoRepresentable(batch.StartedAt)) ||
		(!batch.CompletedAt.IsZero() && !unixNanoRepresentable(batch.CompletedAt)) {
		return pollResult{}, errors.New("conftail poll timestamp is outside the supported range")
	}
	if idle <= 0 {
		return pollResult{}, errors.New("conftail idle duration must be positive")
	}
	if maxDescriptionBytes <= 0 {
		return pollResult{}, errors.New("conftail ticket description limit must be positive")
	}
	startedAt := batch.StartedAt.UTC()
	if startedAt.IsZero() {
		startedAt = batch.EndedAt.UTC()
	}
	events := append([]Event{}, batch.Events...)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].EventAt.Equal(events[j].EventAt) {
			return events[i].SemanticHash < events[j].SemanticHash
		}
		return events[i].EventAt.Before(events[j].EventAt)
	})

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return pollResult{}, fmt.Errorf("begin conftail poll transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result := pollResult{}
	for i := range events {
		if err := validatePersistentEvent(events[i]); err != nil {
			return pollResult{}, fmt.Errorf("validate conftail event: %w", err)
		}
		reconciled, sealed, err := reconcileActiveEventAttribution(
			ctx,
			tx,
			events[i],
			batch.EndedAt.UTC(),
			idle,
			maxDescriptionBytes,
		)
		if err != nil {
			return pollResult{}, err
		}
		if reconciled {
			result.Duplicates++
			result.Sealed += sealed
			continue
		}
		exists, err := eventExists(ctx, tx, events[i])
		if err != nil {
			return pollResult{}, err
		}
		if exists {
			result.Duplicates++
			continue
		}
		sealed, err = placeEvent(
			ctx,
			tx,
			events[i],
			batch.EndedAt.UTC(),
			idle,
			maxDescriptionBytes,
		)
		if err != nil {
			return pollResult{}, err
		}
		result.Inserted++
		result.Sealed += sealed
	}
	sealed, err := finalizeStagedChains(
		ctx,
		tx,
		batch.EndedAt.UTC(),
		maxDescriptionBytes,
	)
	if err != nil {
		return pollResult{}, err
	}
	result.Sealed += sealed
	sealed, err = sealQuietChains(
		ctx,
		tx,
		batch.EndedAt.UTC(),
		idle,
		maxDescriptionBytes,
	)
	if err != nil {
		return pollResult{}, err
	}
	result.Sealed += sealed
	completedAt := batch.CompletedAt.UTC()
	if completedAt.IsZero() || completedAt.Before(startedAt) {
		completedAt = batch.EndedAt.UTC()
	}
	duration := completedAt.Sub(startedAt)
	if duration < 0 {
		duration = 0
	}
	fetched := batch.Fetched
	if fetched == 0 {
		fetched = len(batch.Events)
	}
	_, err = tx.ExecContext(ctx, `UPDATE poll_state SET
		watermark_ns = ?, last_started_at_ns = ?, last_success_at_ns = ?,
		last_duration_ns = ?, last_pages = ?, last_fetched = ?, last_inserted = ?,
		last_error = '', updated_at_ns = ? WHERE id = 1`,
		unixNanos(batch.EndedAt),
		unixNanos(startedAt),
		unixNanos(completedAt),
		duration.Nanoseconds(),
		batch.Pages,
		fetched,
		result.Inserted,
		unixNanos(completedAt),
	)
	if err != nil {
		return pollResult{}, fmt.Errorf("advance conftail watermark: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return pollResult{}, fmt.Errorf("commit conftail poll: %w", err)
	}
	return result, nil
}

func validatePersistentEvent(event Event) error {
	if event.FirewallID <= 0 || event.FirewallName == "" {
		return errors.New("logical firewall is required")
	}
	if event.User == "" {
		return errors.New("attributed user is required")
	}
	switch event.UserAttribution {
	case attributionExact, attributionRecovered, attributionUnattributed:
	default:
		return errors.New("valid user attribution is required")
	}
	if event.SemanticHash == "" || event.CorrelationHash == "" {
		return errors.New("semantic and attribution-correlation hashes are required")
	}
	if event.EventAt.IsZero() || event.IngestedAt.IsZero() {
		return errors.New("event and ingestion timestamps are required")
	}
	if !unixNanoRepresentable(event.EventAt) || !unixNanoRepresentable(event.IngestedAt) {
		return errors.New("event or ingestion timestamp is outside the supported range")
	}
	if _, ok := allowedConfigLogIDs[event.LogID]; !ok {
		return errors.New("unsupported configuration log id")
	}
	for _, value := range []string{
		event.GraylogID,
		event.FirewallName,
		event.Source,
		event.DeviceName,
		event.DeviceID,
		event.VDOM,
		event.User,
		event.UI,
		event.Action,
		event.TransactionID,
		event.Path,
		event.Object,
		event.UUID,
	} {
		if containsSensitiveValueMaterial(value) && !strings.Contains(value, redactedValue) {
			return errors.New("event contains unredacted sensitive material")
		}
	}
	for _, value := range []string{
		event.ConfigAttribute,
		event.LogDescription,
		event.Message,
	} {
		if containsSensitiveMaterial(value) && !strings.Contains(value, redactedValue) {
			return errors.New("event contains unredacted sensitive material")
		}
	}
	return nil
}

func eventExists(ctx context.Context, tx *sql.Tx, event Event) (bool, error) {
	var exists bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM events
		WHERE semantic_hash = ? OR (? != '' AND graylog_id = ?)
	)`, event.SemanticHash, event.GraylogID, event.GraylogID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check conftail event identity: %w", err)
	}
	return exists, nil
}

func reconcileActiveEventAttribution(
	ctx context.Context,
	tx *sql.Tx,
	event Event,
	sealedAt time.Time,
	idle time.Duration,
	maxDescriptionBytes int,
) (bool, int, error) {
	var eventID int64
	var chainID, user, attribution, state string
	var firewallID int
	err := tx.QueryRowContext(ctx, `SELECT
		e.id, e.chain_id, e.firewall_id, e.user, e.user_attribution, c.state
		FROM events e JOIN chains c ON c.id = e.chain_id
		WHERE (? != '' AND e.graylog_id = ?)
			OR (? = 1 AND e.user_was_missing = 1 AND e.correlation_hash = ?)
		ORDER BY CASE WHEN ? != '' AND e.graylog_id = ? THEN 0 ELSE 1 END LIMIT 1`,
		event.GraylogID,
		event.GraylogID,
		boolInt(event.UserWasMissing),
		event.CorrelationHash,
		event.GraylogID,
		event.GraylogID,
	).Scan(
		&eventID,
		&chainID,
		&firewallID,
		&user,
		&attribution,
		&state,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("read duplicate conftail attribution: %w", err)
	}
	if firewallID != event.FirewallID {
		return false, 0, nil
	}
	if state != chainStateActive {
		// Sealed payloads are immutable. A later overlap may improve attribution,
		// but the same raw change must not be persisted and ticketed again.
		return true, 0, nil
	}
	if user == event.User && attribution == event.UserAttribution {
		return false, 0, nil
	}
	// Direct user data is authoritative. A later overlap may refine or revoke
	// only a correlation that was previously inferred from neighboring rows.
	if attribution == attributionExact {
		return false, 0, nil
	}
	if user == event.User {
		result, err := tx.ExecContext(ctx, `UPDATE events SET user_attribution = ? WHERE id = ?`,
			event.UserAttribution, eventID)
		if err != nil {
			return false, 0, fmt.Errorf("refine conftail event attribution: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return false, 0, fmt.Errorf("inspect conftail attribution refinement: %w", err)
		}
		if changed != 1 {
			return false, 0, errors.New("active conftail event disappeared during attribution refinement")
		}
		return true, 0, nil
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE id = ?`, eventID); err != nil {
		return false, 0, fmt.Errorf("remove conftail event for reattribution: %w", err)
	}
	splitSealed, err := rebuildActiveChainAfterEventRemoval(
		ctx,
		tx,
		chainID,
		sealedAt,
		idle,
		maxDescriptionBytes,
	)
	if err != nil {
		return false, 0, err
	}

	exists, err := eventExists(ctx, tx, event)
	if err != nil {
		return false, 0, err
	}
	if exists {
		return true, splitSealed, nil
	}
	sealed, err := placeEvent(ctx, tx, event, sealedAt, idle, maxDescriptionBytes)
	if err != nil {
		return false, 0, fmt.Errorf("reattribute conftail event: %w", err)
	}
	return true, splitSealed + sealed, nil
}

type chainAggregate struct {
	Count        int
	First        int64
	Last         int64
	Created      int64
	Unattributed int
}

func rebuildActiveChainAfterEventRemoval(
	ctx context.Context,
	tx *sql.Tx,
	chainID string,
	sealedAt time.Time,
	idle time.Duration,
	maxDescriptionBytes int,
) (int, error) {
	chain, err := chainByID(ctx, tx, chainID)
	if err != nil {
		return 0, err
	}
	if chain.State != chainStateActive {
		return 0, errors.New("conftail attribution reconciliation requires an active chain")
	}
	all, err := aggregateChainEvents(ctx, tx, chainID, "", 0)
	if err != nil {
		return 0, err
	}
	if all.Count == 0 {
		result, err := tx.ExecContext(ctx, `DELETE FROM chains WHERE id = ? AND state = 'active'`, chainID)
		if err != nil {
			return 0, fmt.Errorf("remove empty conftail chain: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("inspect empty conftail chain removal: %w", err)
		}
		if changed != 1 {
			return 0, errors.New("active conftail chain disappeared during reconciliation")
		}
		return 0, nil
	}

	splitAt, gapCount, err := activeChainSplitPoint(ctx, tx, chainID, idle)
	if err != nil {
		return 0, err
	}
	if gapCount == 0 {
		return 0, updateActiveChainAggregate(ctx, tx, chainID, all)
	}
	if gapCount != 1 {
		return 0, errors.New("conftail active chain has multiple gaps after attribution reconciliation")
	}

	earlier, err := aggregateChainEvents(ctx, tx, chainID, "before", splitAt)
	if err != nil {
		return 0, err
	}
	recent, err := aggregateChainEvents(ctx, tx, chainID, "from", splitAt)
	if err != nil {
		return 0, err
	}
	if earlier.Count == 0 || recent.Count == 0 {
		return 0, errors.New("conftail chain split produced an empty segment")
	}

	sealedChainID := uuid.NewString()
	_, err = tx.ExecContext(ctx, `INSERT INTO chains (
		id, firewall_id, firewall_name, user, first_event_at_ns, last_event_at_ns,
		event_count, state, late, unattributed, sealed_at_ns, created_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?, 'sealed', ?, ?, ?, ?)`,
		sealedChainID,
		chain.FirewallID,
		chain.FirewallName,
		chain.User,
		earlier.First,
		earlier.Last,
		earlier.Count,
		boolInt(chain.Late),
		earlier.Unattributed,
		unixNanos(sealedAt),
		earlier.Created,
	)
	if err != nil {
		return 0, fmt.Errorf("create reconciled sealed conftail chain: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE events SET chain_id = ?
		WHERE chain_id = ? AND event_at_ns < ?`, sealedChainID, chainID, splitAt); err != nil {
		return 0, fmt.Errorf("move reconciled conftail events: %w", err)
	}
	if err := updateActiveChainAggregate(ctx, tx, chainID, recent); err != nil {
		return 0, err
	}
	if err := freezeOutbox(ctx, tx, sealedChainID, sealedAt, maxDescriptionBytes); err != nil {
		return 0, err
	}
	return 1, nil
}

func activeChainSplitPoint(
	ctx context.Context,
	tx *sql.Tx,
	chainID string,
	idle time.Duration,
) (int64, int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT event_at_ns FROM events
		WHERE chain_id = ? ORDER BY event_at_ns, id`, chainID)
	if err != nil {
		return 0, 0, fmt.Errorf("list reconciled conftail event times: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var previous time.Time
	var splitAt int64
	gapCount := 0
	for rows.Next() {
		var eventAt int64
		if err := rows.Scan(&eventAt); err != nil {
			return 0, 0, fmt.Errorf("scan reconciled conftail event time: %w", err)
		}
		current := timeFromNanos(eventAt)
		if !previous.IsZero() && !current.Before(previous.Add(idle)) {
			gapCount++
			splitAt = eventAt
		}
		previous = current
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("iterate reconciled conftail event times: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, 0, fmt.Errorf("close reconciled conftail event times: %w", err)
	}
	return splitAt, gapCount, nil
}

func aggregateChainEvents(
	ctx context.Context,
	tx *sql.Tx,
	chainID string,
	partition string,
	splitAt int64,
) (chainAggregate, error) {
	query := `SELECT COUNT(*), COALESCE(MIN(event_at_ns), 0), COALESCE(MAX(event_at_ns), 0),
		COALESCE(MIN(ingested_at_ns), 0),
		COALESCE(MAX(CASE WHEN user_attribution = 'unattributed' THEN 1 ELSE 0 END), 0)
		FROM events WHERE chain_id = ?`
	args := []any{chainID}
	switch partition {
	case "":
	case "before":
		query += ` AND event_at_ns < ?`
		args = append(args, splitAt)
	case "from":
		query += ` AND event_at_ns >= ?`
		args = append(args, splitAt)
	default:
		return chainAggregate{}, errors.New("invalid conftail chain aggregate partition")
	}
	var aggregate chainAggregate
	if err := tx.QueryRowContext(ctx, query, args...).Scan(
		&aggregate.Count,
		&aggregate.First,
		&aggregate.Last,
		&aggregate.Created,
		&aggregate.Unattributed,
	); err != nil {
		return chainAggregate{}, fmt.Errorf("aggregate reconciled conftail chain: %w", err)
	}
	return aggregate, nil
}

func updateActiveChainAggregate(
	ctx context.Context,
	tx *sql.Tx,
	chainID string,
	aggregate chainAggregate,
) error {
	result, err := tx.ExecContext(ctx, `UPDATE chains SET
		first_event_at_ns = ?, last_event_at_ns = ?, event_count = ?, unattributed = ?
		WHERE id = ? AND state = 'active'`,
		aggregate.First,
		aggregate.Last,
		aggregate.Count,
		aggregate.Unattributed,
		chainID,
	)
	if err != nil {
		return fmt.Errorf("refresh reconciled conftail chain: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect reconciled conftail chain refresh: %w", err)
	}
	if changed != 1 {
		return errors.New("active conftail chain disappeared during reconciliation")
	}
	return nil
}

func activeChain(
	ctx context.Context,
	tx *sql.Tx,
	firewallID int,
	user string,
) (chainRecord, bool, error) {
	var record chainRecord
	var first, last int64
	var late, unattributed int
	err := tx.QueryRowContext(ctx, `SELECT
		id, firewall_id, firewall_name, user, first_event_at_ns, last_event_at_ns,
		event_count, state, late, unattributed
		FROM chains WHERE firewall_id = ? AND user = ? AND state = 'active'`,
		firewallID, user).Scan(
		&record.ID,
		&record.FirewallID,
		&record.FirewallName,
		&record.User,
		&first,
		&last,
		&record.EventCount,
		&record.State,
		&late,
		&unattributed,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return chainRecord{}, false, nil
	}
	if err != nil {
		return chainRecord{}, false, fmt.Errorf("read active conftail chain: %w", err)
	}
	record.FirstEventAt = timeFromNanos(first)
	record.LastEventAt = timeFromNanos(last)
	record.Late = late != 0
	record.Unattributed = unattributed != 0
	return record, true, nil
}

func createActiveChain(
	ctx context.Context,
	tx *sql.Tx,
	event Event,
	isLate bool,
) (chainRecord, error) {
	chain := chainRecord{
		ID:           uuid.NewString(),
		FirewallID:   event.FirewallID,
		FirewallName: event.FirewallName,
		User:         event.User,
		FirstEventAt: event.EventAt.UTC(),
		LastEventAt:  event.EventAt.UTC(),
		EventCount:   1,
		State:        chainStateActive,
		Late:         isLate,
		Unattributed: event.UserAttribution == attributionUnattributed,
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO chains (
		id, firewall_id, firewall_name, user, first_event_at_ns, last_event_at_ns,
		event_count, state, late, unattributed, created_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, 1, 'active', ?, ?, ?)`,
		chain.ID,
		chain.FirewallID,
		chain.FirewallName,
		chain.User,
		unixNanos(chain.FirstEventAt),
		unixNanos(chain.LastEventAt),
		boolInt(chain.Late),
		boolInt(chain.Unattributed),
		unixNanos(event.IngestedAt),
	)
	if err != nil {
		return chainRecord{}, fmt.Errorf("create conftail chain: %w", err)
	}
	event.ChainID = chain.ID
	event.Late = chain.Late
	if err := insertEvent(ctx, tx, event); err != nil {
		return chainRecord{}, err
	}
	return chain, nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, event Event) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO events (
		graylog_id, semantic_hash, correlation_hash, chain_id, firewall_id, firewall_name, source,
		device_name, device_id, vdom, user, user_attribution, ui, action,
		user_was_missing, transaction_id, config_path, config_object, config_attribute, log_id,
		log_description, message, uuid, event_at_ns, ingested_at_ns, late
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.GraylogID,
		event.SemanticHash,
		event.CorrelationHash,
		event.ChainID,
		event.FirewallID,
		event.FirewallName,
		event.Source,
		event.DeviceName,
		event.DeviceID,
		event.VDOM,
		event.User,
		event.UserAttribution,
		event.UI,
		event.Action,
		boolInt(event.UserWasMissing),
		event.TransactionID,
		event.Path,
		event.Object,
		event.ConfigAttribute,
		event.LogID,
		event.LogDescription,
		event.Message,
		event.UUID,
		unixNanos(event.EventAt),
		unixNanos(event.IngestedAt),
		boolInt(event.Late),
	)
	if err != nil {
		return fmt.Errorf("insert conftail event: %w", err)
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func placeEvent(
	ctx context.Context,
	tx *sql.Tx,
	event Event,
	sealedAt time.Time,
	idle time.Duration,
	maxDescriptionBytes int,
) (int, error) {
	chain, found, err := activeChain(ctx, tx, event.FirewallID, event.User)
	if err != nil {
		return 0, err
	}
	if !found {
		isLate, err := isLateArrival(ctx, tx, event, idle)
		if err != nil {
			return 0, err
		}
		_, err = createActiveChain(ctx, tx, event, isLate)
		return 0, err
	}
	if !event.EventAt.Before(chain.LastEventAt) && event.EventAt.Sub(chain.LastEventAt) >= idle {
		if err := sealChain(ctx, tx, chain.ID, sealedAt, maxDescriptionBytes); err != nil {
			return 0, err
		}
		if _, err := createActiveChain(ctx, tx, event, false); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if event.EventAt.Before(chain.FirstEventAt) {
		belongsToSealedChain, err := isLateArrival(ctx, tx, event, idle)
		if err != nil {
			return 0, err
		}
		if belongsToSealedChain || chain.FirstEventAt.Sub(event.EventAt) >= idle {
			if err := stageLateEvent(ctx, tx, event, idle); err != nil {
				return 0, err
			}
			return 0, nil
		}
	}
	if err := appendEvent(ctx, tx, chain, event); err != nil {
		return 0, err
	}
	return 0, nil
}

func appendEvent(ctx context.Context, tx *sql.Tx, chain chainRecord, event Event) error {
	first := chain.FirstEventAt
	if event.EventAt.Before(first) {
		first = event.EventAt
	}
	last := chain.LastEventAt
	if event.EventAt.After(last) {
		last = event.EventAt
	}
	_, err := tx.ExecContext(ctx, `UPDATE chains SET
		first_event_at_ns = ?, last_event_at_ns = ?, event_count = event_count + 1,
		unattributed = CASE WHEN ? = 1 THEN 1 ELSE unattributed END
		WHERE id = ? AND state = 'active'`,
		unixNanos(first),
		unixNanos(last),
		boolInt(event.UserAttribution == attributionUnattributed),
		chain.ID,
	)
	if err != nil {
		return fmt.Errorf("update active conftail chain: %w", err)
	}
	event.ChainID = chain.ID
	event.Late = chain.Late
	return insertEvent(ctx, tx, event)
}

func isLateArrival(ctx context.Context, tx *sql.Tx, event Event, idle time.Duration) (bool, error) {
	var lastEventNanos int64
	err := tx.QueryRowContext(ctx, `SELECT last_event_at_ns FROM chains
		WHERE firewall_id = ? AND user = ? AND state = 'sealed'
		ORDER BY last_event_at_ns DESC LIMIT 1`, event.FirewallID, event.User).Scan(&lastEventNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read latest sealed conftail chain: %w", err)
	}
	return event.EventAt.Before(timeFromNanos(lastEventNanos).Add(idle)), nil
}

func sealQuietChains(
	ctx context.Context,
	tx *sql.Tx,
	endedAt time.Time,
	idle time.Duration,
	maxDescriptionBytes int,
) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM chains
		WHERE state = 'active' AND last_event_at_ns <= ? ORDER BY last_event_at_ns, id`,
		unixNanos(endedAt.Add(-idle)))
	if err != nil {
		return 0, fmt.Errorf("list quiet conftail chains: %w", err)
	}
	chainIDs := []string{}
	for rows.Next() {
		var chainID string
		if err := rows.Scan(&chainID); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan quiet conftail chain: %w", err)
		}
		chainIDs = append(chainIDs, chainID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("iterate quiet conftail chains: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close quiet conftail chain rows: %w", err)
	}
	for _, chainID := range chainIDs {
		if err := sealChain(ctx, tx, chainID, endedAt, maxDescriptionBytes); err != nil {
			return 0, err
		}
	}
	return len(chainIDs), nil
}

func sealChain(
	ctx context.Context,
	tx *sql.Tx,
	chainID string,
	sealedAt time.Time,
	maxDescriptionBytes int,
) error {
	result, err := tx.ExecContext(ctx, `UPDATE chains SET state = 'sealed', sealed_at_ns = ?
		WHERE id = ? AND state = 'active'`, unixNanos(sealedAt), chainID)
	if err != nil {
		return fmt.Errorf("seal conftail chain: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect sealed conftail chain: %w", err)
	}
	if changed != 1 {
		return errors.New("active conftail chain disappeared during sealing")
	}
	return freezeOutbox(ctx, tx, chainID, sealedAt, maxDescriptionBytes)
}

func stageLateEvent(
	ctx context.Context,
	tx *sql.Tx,
	event Event,
	idle time.Duration,
) error {
	chain, found, err := latestStagingChain(ctx, tx, event.FirewallID, event.User)
	if err != nil {
		return err
	}
	if found {
		gap := time.Duration(0)
		switch {
		case event.EventAt.Before(chain.FirstEventAt):
			gap = chain.FirstEventAt.Sub(event.EventAt)
		case event.EventAt.After(chain.LastEventAt):
			gap = event.EventAt.Sub(chain.LastEventAt)
		}
		if gap < idle {
			return appendStagedEvent(ctx, tx, chain, event)
		}
	}

	chainID := uuid.NewString()
	unattributed := event.UserAttribution == attributionUnattributed
	_, err = tx.ExecContext(ctx, `INSERT INTO chains (
		id, firewall_id, firewall_name, user, first_event_at_ns, last_event_at_ns,
		event_count, state, late, unattributed, sealed_at_ns, created_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, 1, 'staging', 1, ?, 0, ?)`,
		chainID,
		event.FirewallID,
		event.FirewallName,
		event.User,
		unixNanos(event.EventAt),
		unixNanos(event.EventAt),
		boolInt(unattributed),
		unixNanos(event.IngestedAt),
	)
	if err != nil {
		return fmt.Errorf("stage late conftail chain: %w", err)
	}
	event.ChainID = chainID
	event.Late = true
	return insertEvent(ctx, tx, event)
}

func latestStagingChain(
	ctx context.Context,
	tx *sql.Tx,
	firewallID int,
	user string,
) (chainRecord, bool, error) {
	var chain chainRecord
	var first, last int64
	var late, unattributed int
	err := tx.QueryRowContext(ctx, `SELECT
		id, firewall_id, firewall_name, user, first_event_at_ns, last_event_at_ns,
		event_count, state, late, unattributed
		FROM chains WHERE firewall_id = ? AND user = ? AND state = 'staging'
		ORDER BY last_event_at_ns DESC, id DESC LIMIT 1`, firewallID, user).Scan(
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
	)
	if errors.Is(err, sql.ErrNoRows) {
		return chainRecord{}, false, nil
	}
	if err != nil {
		return chainRecord{}, false, fmt.Errorf("read staged late conftail chain: %w", err)
	}
	chain.FirstEventAt = timeFromNanos(first)
	chain.LastEventAt = timeFromNanos(last)
	chain.Late = late != 0
	chain.Unattributed = unattributed != 0
	return chain, true, nil
}

func appendStagedEvent(ctx context.Context, tx *sql.Tx, chain chainRecord, event Event) error {
	first := chain.FirstEventAt
	if event.EventAt.Before(first) {
		first = event.EventAt
	}
	last := chain.LastEventAt
	if event.EventAt.After(last) {
		last = event.EventAt
	}
	result, err := tx.ExecContext(ctx, `UPDATE chains SET
		first_event_at_ns = ?, last_event_at_ns = ?, event_count = event_count + 1,
		unattributed = CASE WHEN ? = 1 THEN 1 ELSE unattributed END
		WHERE id = ? AND state = 'staging'`,
		unixNanos(first),
		unixNanos(last),
		boolInt(event.UserAttribution == attributionUnattributed),
		chain.ID,
	)
	if err != nil {
		return fmt.Errorf("append staged late conftail event: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect staged late conftail event: %w", err)
	}
	if changed != 1 {
		return errors.New("staged late conftail chain disappeared")
	}
	event.ChainID = chain.ID
	event.Late = true
	return insertEvent(ctx, tx, event)
}

func finalizeStagedChains(
	ctx context.Context,
	tx *sql.Tx,
	sealedAt time.Time,
	maxDescriptionBytes int,
) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM chains
		WHERE state = 'staging' ORDER BY first_event_at_ns, id`)
	if err != nil {
		return 0, fmt.Errorf("list staged late conftail chains: %w", err)
	}
	chainIDs := []string{}
	for rows.Next() {
		var chainID string
		if err := rows.Scan(&chainID); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan staged late conftail chain: %w", err)
		}
		chainIDs = append(chainIDs, chainID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("iterate staged late conftail chains: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close staged late conftail chains: %w", err)
	}

	for _, chainID := range chainIDs {
		result, err := tx.ExecContext(ctx, `UPDATE chains SET state = 'sealed', sealed_at_ns = ?
			WHERE id = ? AND state = 'staging'`, unixNanos(sealedAt), chainID)
		if err != nil {
			return 0, fmt.Errorf("seal staged late conftail chain: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("inspect sealed staged conftail chain: %w", err)
		}
		if changed != 1 {
			return 0, errors.New("staged late conftail chain disappeared during sealing")
		}
		if err := freezeOutbox(ctx, tx, chainID, sealedAt, maxDescriptionBytes); err != nil {
			return 0, err
		}
	}
	return len(chainIDs), nil
}

func freezeOutbox(
	ctx context.Context,
	tx *sql.Tx,
	chainID string,
	sealedAt time.Time,
	maxDescriptionBytes int,
) error {
	chain, err := chainByID(ctx, tx, chainID)
	if err != nil {
		return err
	}
	events, err := eventsForChain(ctx, tx, chainID, maxDescriptionBytes)
	if err != nil {
		return err
	}
	payload, err := buildTicketPayload(chain, events, maxDescriptionBytes)
	if err != nil {
		return fmt.Errorf("build conftail ticket payload: %w", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode conftail ticket payload: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox (
		chain_id, payload_json, state, next_attempt_at_ns, updated_at_ns
	) VALUES (?, ?, 'pending', ?, ?)`,
		chainID,
		encoded,
		unixNanos(sealedAt),
		unixNanos(sealedAt),
	)
	if err != nil {
		return fmt.Errorf("freeze conftail outbox payload: %w", err)
	}
	return nil
}

func chainByID(ctx context.Context, tx *sql.Tx, chainID string) (chainRecord, error) {
	var chain chainRecord
	var first, last, sealed int64
	var late, unattributed int
	err := tx.QueryRowContext(ctx, `SELECT
		id, firewall_id, firewall_name, user, first_event_at_ns, last_event_at_ns,
		event_count, state, late, unattributed, sealed_at_ns
		FROM chains WHERE id = ?`, chainID).Scan(
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
	)
	if err != nil {
		return chainRecord{}, fmt.Errorf("read conftail chain: %w", err)
	}
	chain.FirstEventAt = timeFromNanos(first)
	chain.LastEventAt = timeFromNanos(last)
	chain.SealedAt = timeFromNanos(sealed)
	chain.Late = late != 0
	chain.Unattributed = unattributed != 0
	return chain, nil
}

func eventsForChain(
	ctx context.Context,
	tx *sql.Tx,
	chainID string,
	maxDescriptionBytes int,
) ([]Event, error) {
	if maxDescriptionBytes < 1 {
		return nil, errors.New("conftail ticket description limit is invalid")
	}
	rows, err := tx.QueryContext(ctx, `SELECT
		graylog_id, semantic_hash, firewall_id, firewall_name, source, device_name,
		device_id, vdom, user, user_attribution, ui, action, transaction_id,
		config_path, config_object, config_attribute, log_id, log_description,
		message, uuid, event_at_ns, ingested_at_ns, late
		FROM events WHERE chain_id = ? ORDER BY event_at_ns, semantic_hash`,
		chainID,
	)
	if err != nil {
		return nil, fmt.Errorf("list conftail chain events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	events := make([]Event, 0, 128)
	loadedBytes := 0
	for rows.Next() {
		var event Event
		var eventAt, ingestedAt int64
		var late int
		err := rows.Scan(
			&event.GraylogID,
			&event.SemanticHash,
			&event.FirewallID,
			&event.FirewallName,
			&event.Source,
			&event.DeviceName,
			&event.DeviceID,
			&event.VDOM,
			&event.User,
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
			&event.UUID,
			&eventAt,
			&ingestedAt,
			&late,
		)
		if err != nil {
			return nil, fmt.Errorf("scan conftail chain event: %w", err)
		}
		event.ChainID = chainID
		event.EventAt = timeFromNanos(eventAt)
		event.IngestedAt = timeFromNanos(ingestedAt)
		event.Late = late != 0
		eventBytes := len(timelineLine(event))
		if len(events) > 0 && loadedBytes+eventBytes > maxDescriptionBytes {
			break
		}
		events = append(events, event)
		loadedBytes += eventBytes
		if loadedBytes >= maxDescriptionBytes {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate conftail chain events: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close conftail chain events: %w", err)
	}
	return events, nil
}

type outboxDelivery struct {
	ChainID     string
	Payload     []byte
	State       string
	Attempts    int
	NextAttempt time.Time
}

func (s *store) dueDeliveries(
	ctx context.Context,
	now time.Time,
	limit int,
) ([]outboxDelivery, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("conftail delivery limit must be between 1 and 100")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT
		chain_id, payload_json, state, attempt_count, next_attempt_at_ns
		FROM outbox
		WHERE state IN ('pending','retry','failed') AND next_attempt_at_ns <= ?
		ORDER BY next_attempt_at_ns, chain_id LIMIT ?`, unixNanos(now), limit)
	if err != nil {
		return nil, fmt.Errorf("list due conftail deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	deliveries := []outboxDelivery{}
	for rows.Next() {
		var delivery outboxDelivery
		var nextAttempt int64
		if err := rows.Scan(
			&delivery.ChainID,
			&delivery.Payload,
			&delivery.State,
			&delivery.Attempts,
			&nextAttempt,
		); err != nil {
			return nil, fmt.Errorf("scan due conftail delivery: %w", err)
		}
		delivery.NextAttempt = timeFromNanos(nextAttempt)
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate due conftail deliveries: %w", err)
	}
	return deliveries, nil
}

func (s *store) markAccepted(
	ctx context.Context,
	chainID string,
	requestID string,
	acceptedAt time.Time,
) error {
	result, err := s.db.ExecContext(ctx, `UPDATE outbox SET
		state = 'accepted', attempt_count = attempt_count + 1, request_id = ?,
		accepted_at_ns = ?, last_error = '', updated_at_ns = ?
		WHERE chain_id = ? AND state != 'accepted'`,
		truncateString(requestID, maxIdentityRunes),
		unixNanos(acceptedAt),
		unixNanos(acceptedAt),
		chainID,
	)
	if err != nil {
		return fmt.Errorf("accept conftail outbox delivery: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect accepted conftail delivery: %w", err)
	}
	if changed != 1 {
		return errors.New("pending conftail delivery not found")
	}
	return nil
}

func (s *store) markDeliveryFailure(
	ctx context.Context,
	chainID string,
	state string,
	nextAttempt time.Time,
	deliveryErr error,
	now time.Time,
) error {
	if state != deliveryStateRetry && state != deliveryStateFailed {
		return errors.New("invalid conftail delivery failure state")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE outbox SET
		state = ?, attempt_count = attempt_count + 1, next_attempt_at_ns = ?,
		last_error = ?, updated_at_ns = ?
		WHERE chain_id = ? AND state != 'accepted'`,
		state,
		unixNanos(nextAttempt),
		sanitizeDeliveryError(deliveryErr),
		unixNanos(now),
		chainID,
	)
	if err != nil {
		return fmt.Errorf("record conftail delivery failure: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect conftail delivery failure: %w", err)
	}
	if changed != 1 {
		return errors.New("pending conftail delivery not found")
	}
	return nil
}

func sanitizeDeliveryError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t':
			return ' '
		default:
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}
	}, err.Error())
	return truncateString(value, maxIdentityRunes)
}

func (s *store) prune(ctx context.Context, now time.Time, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := now.UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	result, err := s.db.ExecContext(ctx, `DELETE FROM chains WHERE id IN (
		SELECT chains.id FROM chains
		JOIN outbox ON outbox.chain_id = chains.id
		WHERE chains.state = 'sealed' AND outbox.state = 'accepted'
		  AND outbox.accepted_at_ns > 0 AND outbox.accepted_at_ns < ?
	)`, unixNanos(cutoff))
	if err != nil {
		return 0, fmt.Errorf("prune accepted conftail history: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("inspect pruned conftail history: %w", err)
	}
	return int(deleted), nil
}
