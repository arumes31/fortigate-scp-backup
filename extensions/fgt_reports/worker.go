package fgt_reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/arumes31/fortigate-scp-backup/extensions/fgt_reports/renderpdf"
	"github.com/arumes31/fortigate-scp-backup/internal/fortiosconfig"
	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

const maxReportSetBytes = 64 << 20

type reportData struct {
	Source     reportmodel.Source     `json:"source"`
	Assessment reportmodel.Assessment `json:"assessment"`
	Language   string                 `json:"language"`
	Version    string                 `json:"version"`
}

func (e *Extension) generate(t target) {
	ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
	defer cancel()
	if e.broadcast != nil {
		e.broadcast("reports", t.FirewallID, "started")
		defer e.broadcast("reports", t.FirewallID, "finished")
	}
	stage := "source"
	failure := func() {
		// Raw parser values, decrypted configuration and renderer errors must not
		// enter activity logs or HTML. The stage is enough to request a safe retry.
		e.logger.Warn("automatic report generation failed", "firewall_id", t.FirewallID, "backup_id", t.BackupID, "stage", stage)
		if e.ctx.Err() != nil {
			return
		} // restart recovery requeues running work
		writeCtx, writeCancel := context.WithTimeout(e.ctx, 5*time.Second)
		defer writeCancel()
		if err := failTarget(writeCtx, e.db, t, stage, time.Now()); err != nil {
			e.logger.Warn("report failure status could not be persisted", "firewall_id", t.FirewallID)
		}
	}
	// Reporting is an optional background consumer. A malformed configuration
	// or renderer defect must not take down the backup service.
	defer func() {
		if recover() != nil {
			failure()
		}
	}()
	source, plain, err := e.readSource(ctx, t.FirewallID, t.BackupID)
	if err != nil {
		failure()
		return
	}
	defer clear(plain)
	if source.FirewallID != t.FirewallID || source.BackupID != t.BackupID || source.BackupAt.UnixNano() != t.BackupNS ||
		(t.Checksum != "" && source.Checksum != t.Checksum) {
		clear(plain)
		failure()
		return
	}
	stage = "analysis"
	analyze := e.analyze
	if analyze == nil {
		analyze = fortiosconfig.Analyze
	}
	assessment, err := analyze(ctx, plain)
	clear(plain)
	if err != nil {
		failure()
		return
	}
	source.GeneratedAt = time.Now().UTC()
	data := reportData{Source: source, Assessment: assessment, Language: e.cfg.ReportsLanguage, Version: reportmodel.Version}
	stage = "rendering"
	set, err := e.buildSet(ctx, data)
	if err != nil {
		failure()
		return
	}
	stage = "source"
	// A newer backup may have arrived while rendering. Reconcile before the
	// compare-and-swap publication so late older work cannot replace newer work.
	if err := e.refresh(ctx); err != nil {
		failure()
		return
	}
	stage = "storage"
	published, err := publish(ctx, e.db, t, source.GeneratedAt, set)
	if err != nil {
		failure()
		return
	}
	if published && e.logActivity != nil {
		e.logActivity("system", "reports.generated", fmt.Sprintf("firewall_id=%d backup_id=%d types=forwarding,technical,customer", t.FirewallID, t.BackupID))
	}
}

func (e *Extension) buildSet(ctx context.Context, data reportData) (encryptedSet, error) {
	set := encryptedSet{Limited: !data.Assessment.Complete}
	summary, err := json.Marshal(data)
	if err != nil {
		return set, err
	}
	if len(summary) > maxReportSetBytes {
		return set, errors.New("report assessment exceeds limit")
	}
	set.Assessment, err = e.cipher.Encrypt(summary)
	if err != nil {
		return set, err
	}
	total := len(summary)
	render := e.render
	if render == nil {
		render = renderpdf.Render
	}
	for _, item := range []struct {
		kind        string
		destination *[]byte
	}{
		{"forwarding", &set.Forwarding}, {"technical", &set.Technical}, {"customer", &set.Customer},
	} {
		if err := ctx.Err(); err != nil {
			return set, err
		}
		pdf, err := render(ctx, data.Source, data.Assessment, item.kind, data.Language)
		if err != nil {
			return set, err
		}
		total += len(pdf)
		if total > maxReportSetBytes {
			return set, errors.New("report set exceeds limit")
		}
		*item.destination, err = e.cipher.Encrypt(pdf)
		if err != nil {
			return set, err
		}
	}
	return set, nil
}
