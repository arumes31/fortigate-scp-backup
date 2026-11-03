package fgt_reports

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

const maxProfileBytes = 512 << 10

var errProfileConflict = errors.New("the report profile changed; reload it before saving")

type savedProfile struct {
	Profile reportmodel.Profile
	NextDue time.Time
}

func profileGeneration(p reportmodel.Profile) string {
	return reportmodel.Version + ":" + reportmodel.ProfileHash(p)
}

func (e *Extension) decodeProfile(encrypted []byte) (reportmodel.Profile, error) {
	var p reportmodel.Profile
	if len(encrypted) > maxProfileBytes+1024 {
		return p, errors.New("stored report profile exceeds limit")
	}
	plain, err := e.cipher.Decrypt(encrypted)
	if err != nil {
		return p, errors.New("report profile authentication failed")
	}
	defer clear(plain)
	if err := decodeProfileJSON(plain, &p); err != nil {
		return p, err
	}
	return reportmodel.NormalizeProfile(p)
}

func decodeProfileJSON(data []byte, into any) error {
	if len(data) > maxProfileBytes {
		return errors.New("report profile exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(into); err != nil {
		return errors.New("invalid report profile document")
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("report profile must contain one JSON document")
	}
	return nil
}

func (e *Extension) getProfile(ctx context.Context, firewallID int) (savedProfile, error) {
	return e.readProfile(ctx, e.db, firewallID)
}

type profileReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (e *Extension) readProfile(ctx context.Context, reader profileReader, firewallID int) (savedProfile, error) {
	var encrypted []byte
	var nextNS int64
	err := reader.QueryRowContext(ctx, "SELECT document,next_due_ns FROM report_profiles WHERE firewall_id=?", firewallID).Scan(&encrypted, &nextNS)
	if errors.Is(err, sql.ErrNoRows) {
		return savedProfile{Profile: reportmodel.DefaultProfile(e.cfg.ReportsLanguage)}, nil
	}
	if err != nil {
		return savedProfile{}, err
	}
	p, err := e.decodeProfile(encrypted)
	if err != nil {
		return savedProfile{}, err
	}
	result := savedProfile{Profile: p}
	if nextNS > 0 {
		result.NextDue = time.Unix(0, nextNS).UTC()
	}
	return result, nil
}

func (e *Extension) allProfiles(ctx context.Context) (map[int]savedProfile, error) {
	rows, err := e.db.QueryContext(ctx, "SELECT firewall_id,document,next_due_ns FROM report_profiles")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	result := make(map[int]savedProfile)
	for rows.Next() {
		var id int
		var encrypted []byte
		var nextNS int64
		if err := rows.Scan(&id, &encrypted, &nextNS); err != nil {
			return nil, err
		}
		p, err := e.decodeProfile(encrypted)
		if err != nil {
			return nil, err
		}
		s := savedProfile{Profile: p}
		if nextNS > 0 {
			s.NextDue = time.Unix(0, nextNS).UTC()
		}
		result[id] = s
	}
	return result, rows.Err()
}

// saveProfile updates a single current definition and the desired generation in
// one transaction. A renderer holding an older profile cannot publish afterward.
func (e *Extension) saveProfile(ctx context.Context, source reportmodel.Source, p reportmodel.Profile, expected string, reset bool) error {
	p, err := reportmodel.NormalizeProfile(p)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer clear(plain)
	if len(plain) > maxProfileBytes {
		return errors.New("report profile exceeds limit")
	}
	encrypted, err := e.cipher.Encrypt(plain)
	if err != nil {
		return err
	}
	next, err := nextScheduledRun(p.Schedule, time.Now())
	if err != nil {
		return err
	}
	nextNS := int64(0)
	if !next.IsZero() {
		nextNS = next.UnixNano()
	}
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var current []byte
	err = tx.QueryRowContext(ctx, "SELECT document FROM report_profiles WHERE firewall_id=?", source.FirewallID).Scan(&current)
	prior := reportmodel.DefaultProfile(e.cfg.ReportsLanguage)
	if err == nil {
		prior, err = e.decodeProfile(current)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if expected != "" && expected != reportmodel.ProfileHash(prior) {
		return errProfileConflict
	}
	generation := profileGeneration(p)
	if _, err := tx.ExecContext(ctx, enqueueSQL, source.FirewallID, source.BackupID, source.BackupAt.UnixNano(), source.Checksum, generation); err != nil {
		return err
	}
	if reset {
		_, err = tx.ExecContext(ctx, "DELETE FROM report_profiles WHERE firewall_id=?", source.FirewallID)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO report_profiles(firewall_id,document,next_due_ns,last_scheduled_ns)
 VALUES (?,?,?,0) ON CONFLICT(firewall_id) DO UPDATE SET document=excluded.document,next_due_ns=excluded.next_due_ns,last_scheduled_ns=0`, source.FirewallID, encrypted, nextNS)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE report_targets SET generation=?,status='queued',error='',attempts=0,retry_ns=0 WHERE firewall_id=?`, generation, source.FirewallID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	e.signal()
	return nil
}

// enqueueScheduled coalesces missed occurrences into one latest-source job.
// The persisted next occurrence and queue transition are atomic across restarts.
func (e *Extension) enqueueScheduled(ctx context.Context, now time.Time) error {
	profiles, err := e.allProfiles(ctx)
	if err != nil {
		return err
	}
	for id, saved := range profiles {
		if saved.NextDue.IsZero() || saved.NextDue.After(now) {
			continue
		}
		next, err := nextScheduledRun(saved.Profile.Schedule, now)
		if err != nil {
			return err
		}
		if err := e.enqueueOccurrence(ctx, id, saved.NextDue, next, now, profileGeneration(saved.Profile)); err != nil {
			return err
		}
	}
	return nil
}

func (e *Extension) enqueueOccurrence(ctx context.Context, id int, due, next, now time.Time, generation string) error {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var status string
	if err := tx.QueryRowContext(ctx, "SELECT status FROM report_targets WHERE firewall_id=?", id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if status == "running" || status == "queued" {
		// The active/new-backup job already satisfies this request. Consume the
		// occurrence without replacing its identity or resetting its retry count.
		_, err = tx.ExecContext(ctx, `UPDATE report_profiles SET next_due_ns=?,last_scheduled_ns=? WHERE firewall_id=? AND next_due_ns=?
 AND (SELECT generation FROM report_targets WHERE firewall_id=report_profiles.firewall_id)=?`, next.UnixNano(), now.UnixNano(), id, due.UnixNano(), generation)
	} else {
		var changed sql.Result
		changed, err = tx.ExecContext(ctx, `UPDATE report_profiles SET next_due_ns=?,last_scheduled_ns=? WHERE firewall_id=? AND next_due_ns=?
 AND (SELECT generation FROM report_targets WHERE firewall_id=report_profiles.firewall_id)=?`, next.UnixNano(), now.UnixNano(), id, due.UnixNano(), generation)
		if err == nil {
			var count int64
			count, err = changed.RowsAffected()
			if err == nil && count == 1 {
				_, err = tx.ExecContext(ctx, "UPDATE report_targets SET status='queued',error='',attempts=0,retry_ns=0 WHERE firewall_id=?", id)
			}
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
