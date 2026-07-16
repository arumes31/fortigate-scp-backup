package fgt_polsplit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
)

// ErrNotFound is returned by loadBackup when the firewall or backup does not
// exist, allowing handlers to distinguish 404 from unexpected failures.
var ErrNotFound = errors.New("not found")

// maxTuplesInResponse caps the observed-traffic table sent to the UI; the
// strategies are always computed over the full tuple set.
const maxTuplesInResponse = 500

// maxRangeSeconds bounds relative/absolute analysis windows (90 days).
const maxRangeSeconds = 90 * 24 * 3600

func (e *Extension) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (e *Extension) jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (e *Extension) index(w http.ResponseWriter, r *http.Request) {
	firewalls, err := e.fetchFirewalls(r.Context())
	if err != nil {
		e.logger.Error("polsplit: failed to fetch firewalls", "err", err)
	}
	data := struct {
		Base      baseData
		Firewalls []FirewallRef
	}{
		Base:      e.baseData(r, "Policy Split Advisor", "polsplit"),
		Firewalls: firewalls,
	}
	if err := e.tmpl.ExecuteTemplate(w, "fgt_polsplit_index.html", data); err != nil {
		e.logger.Error("polsplit: template render failed", "err", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (e *Extension) fetchFirewalls(ctx context.Context) ([]FirewallRef, error) {
	rows, err := e.pgPool.Query(ctx, "SELECT id, fqdn FROM firewalls ORDER BY fqdn")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []FirewallRef
	for rows.Next() {
		var fw FirewallRef
		if err := rows.Scan(&fw.ID, &fw.FQDN); err != nil {
			return nil, err
		}
		list = append(list, fw)
	}
	return list, rows.Err()
}

func (e *Extension) listFirewalls(w http.ResponseWriter, r *http.Request) {
	list, err := e.fetchFirewalls(r.Context())
	if err != nil {
		e.jsonError(w, http.StatusInternalServerError, "Database error")
		return
	}
	e.writeJSON(w, map[string]any{"firewalls": list})
}

// loadBackup returns the firewall's FQDN plus the decrypted latest config
// backup and its timestamp.
func (e *Extension) loadBackup(ctx context.Context, fwID int) (fqdn, content string, ts time.Time, err error) {
	if err = e.pgPool.QueryRow(ctx, `SELECT fqdn FROM firewalls WHERE id = $1`, fwID).Scan(&fqdn); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ts, fmt.Errorf("%w: firewall %d not found", ErrNotFound, fwID)
		}
		return "", "", ts, err
	}
	var filename string
	err = e.pgPool.QueryRow(ctx,
		"SELECT filename, timestamp FROM backups WHERE fw_id = $1 ORDER BY timestamp DESC LIMIT 1", fwID).Scan(&filename, &ts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ts, fmt.Errorf("%w: no backups found for firewall %d", ErrNotFound, fwID)
		}
		return "", "", ts, err
	}
	diskPath := filepath.Join(e.cfg.BackupDir, filepath.FromSlash(filename))
	encData, err := os.ReadFile(diskPath)
	if err != nil {
		e.logger.Error("polsplit: failed to read backup file", "path", diskPath, "err", err)
		return "", "", ts, errors.New("failed to read backup file from disk")
	}
	cipher, err := crypto.New(e.cfg.EncryptionKey)
	if err != nil {
		return "", "", ts, errors.New("failed to init cipher")
	}
	plain, err := cipher.Decrypt(encData)
	if err != nil {
		e.logger.Error("polsplit: failed to decrypt backup", "path", diskPath, "err", err)
		return "", "", ts, errors.New("failed to decrypt backup")
	}
	return fqdn, string(plain), ts, nil
}

// policyInfo loads the target policy from the latest backup so the UI can show
// what is about to be split before running the (heavier) log analysis.
func (e *Extension) policyInfo(w http.ResponseWriter, r *http.Request) {
	fwID, err1 := strconv.Atoi(r.URL.Query().Get("fw_id"))
	policyID, err2 := strconv.Atoi(r.URL.Query().Get("policy_id"))
	if err1 != nil || err2 != nil || policyID < 0 {
		e.jsonError(w, http.StatusBadRequest, "invalid fw_id / policy_id")
		return
	}
	vdom := r.URL.Query().Get("vdom")
	fqdn, content, ts, err := e.loadBackup(r.Context(), fwID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			e.jsonError(w, http.StatusNotFound, err.Error())
		} else {
			e.logger.Error("polsplit: loadBackup failed", "err", err)
			e.jsonError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}
	parsed := ParseBackup(content, policyID, vdom)
	if len(parsed.PolicyVDOMs) > 1 && vdom == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":     fmt.Sprintf("policy ID %d matches multiple VDOMs: %v", policyID, parsed.PolicyVDOMs),
			"ambiguous": true,
			"vdoms":     parsed.PolicyVDOMs,
		})
		return
	}
	if parsed.Policy == nil {
		e.jsonError(w, http.StatusNotFound,
			fmt.Sprintf("policy %d not found in the latest backup of %s (%s)", policyID, fqdn, ts.Format("2006-01-02 15:04")))
		return
	}
	if parsed.Policy.Action != "accept" {
		e.jsonError(w, http.StatusBadRequest, fmt.Sprintf("policy %d has action %q — only accept policies can be split", policyID, displayAction(parsed.Policy.Action)))
		return
	}
	warnings := policyWarnings(parsed.Policy)
	e.log(r, "PolSplit Info", fmt.Sprintf("Loaded policy %d of firewall %d", policyID, fwID))
	e.writeJSON(w, map[string]any{
		"firewall":             FirewallRef{ID: fwID, FQDN: fqdn},
		"policy":               parsed.Policy,
		"action_display":       displayAction(parsed.Policy.Action),
		"backup_time":          ts.In(e.tz).Format("2006-01-02 15:04"),
		"used_policy_id_count": len(parsed.UsedPolicyIDs),
		"warnings":             warnings,
	})
}

// policyWarnings flags target-policy states the operator should see before
// acting on an analysis.
func policyWarnings(p *OrigPolicy) []string {
	var w []string
	if p.Status == "disable" {
		w = append(w, "this policy is currently DISABLED — it carries no traffic, so the analysis reflects only logs from when it was active")
	}
	return w
}

type analyzeRequest struct {
	FwID            int    `json:"fw_id"`
	PolicyID        int    `json:"policy_id"`
	VDOM            string `json:"vdom"`
	RangeSeconds    int    `json:"range_seconds"` // preset; 0 = custom absolute range
	From            string `json:"from"`          // ISO-8601 (custom range)
	To              string `json:"to"`
	RollupSrc       bool   `json:"rollup_src"`
	RollupDst       bool   `json:"rollup_dst"`
	RollupThreshold int    `json:"rollup_threshold"`
	RollupMask      int    `json:"rollup_mask"`
	Prefix          string `json:"prefix"`
}

// parseTimeRange validates the requested window and converts a custom range to
// the Graylog absolute format (UTC, millisecond precision).
func parseTimeRange(req analyzeRequest) (timeRange, error) {
	if req.RangeSeconds > 0 {
		if req.RangeSeconds > maxRangeSeconds {
			return timeRange{}, fmt.Errorf("range too large (max %d days)", maxRangeSeconds/86400)
		}
		return timeRange{RelativeSec: req.RangeSeconds}, nil
	}
	from, err := time.Parse(time.RFC3339, req.From)
	if err != nil {
		return timeRange{}, fmt.Errorf("invalid custom range start: %v", err)
	}
	to, err := time.Parse(time.RFC3339, req.To)
	if err != nil {
		return timeRange{}, fmt.Errorf("invalid custom range end: %v", err)
	}
	if !to.After(from) {
		return timeRange{}, errors.New("custom range end must be after start")
	}
	if to.Sub(from) > maxRangeSeconds*time.Second {
		return timeRange{}, fmt.Errorf("custom range too large (max %d days)", maxRangeSeconds/86400)
	}
	const layout = "2006-01-02T15:04:05.000Z"
	return timeRange{From: from.UTC().Format(layout), To: to.UTC().Format(layout)}, nil
}

func (e *Extension) analyze(w http.ResponseWriter, r *http.Request) {
	var req analyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		e.jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	tr, err := parseTimeRange(req)
	if err != nil {
		e.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	fqdn, content, ts, err := e.loadBackup(r.Context(), req.FwID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			e.jsonError(w, http.StatusNotFound, err.Error())
		} else {
			e.logger.Error("polsplit: loadBackup failed", "err", err)
			e.jsonError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}
	parsed := ParseBackup(content, req.PolicyID, req.VDOM)
	if len(parsed.PolicyVDOMs) > 1 && req.VDOM == "" {
		e.jsonError(w, http.StatusBadRequest,
			fmt.Sprintf("policy ID %d is ambiguous (matches multiple VDOMs: %v); please specify a vdom selection", req.PolicyID, parsed.PolicyVDOMs))
		return
	}
	if parsed.Policy == nil {
		e.jsonError(w, http.StatusNotFound,
			fmt.Sprintf("policy %d not found in the latest backup of %s", req.PolicyID, fqdn))
		return
	}
	if parsed.Policy.Action != "accept" {
		e.jsonError(w, http.StatusBadRequest, fmt.Sprintf("policy %d has action %q — only accept policies can be split", req.PolicyID, displayAction(parsed.Policy.Action)))
		return
	}

	tuples, totalMessages, warnings, err := e.fetchPolicyTraffic(r.Context(), fqdn, req.PolicyID, parsed.Policy.VDOM, tr)
	if err != nil {
		e.jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	warnings = append(warnings, policyWarnings(parsed.Policy)...)
	if totalMessages > 0 && len(tuples) == 0 {
		warnings = append(warnings, fmt.Sprintf("%d log messages matched but none carried usable srcip/dstip fields — check the Graylog field extraction or GRAYLOG_POLSPLIT_QUERY", totalMessages))
	}
	if totalMessages == 0 {
		warnings = append(warnings, "no log messages matched — verify the firewall's Graylog source mapping, the policy ID, and that the policy has logtraffic enabled")
	}

	analysis := Analyze(tuples, AnalyzeOptions{
		RollupSrc:       req.RollupSrc,
		RollupDst:       req.RollupDst,
		RollupThreshold: req.RollupThreshold,
		RollupMask:      req.RollupMask,
	})
	warnings = append(warnings, analysis.Warnings...)

	prefix := req.Prefix
	if prefix == "" {
		prefix = fmt.Sprintf("PS%d", req.PolicyID)
	}

	strategies := []Strategy{
		{Key: "per_service", Label: "One policy per service"},
		{Key: "per_destination", Label: "One policy per destination"},
	}
	for i := range strategies {
		var pols []RecPolicy
		switch strategies[i].Key {
		case "per_service":
			pols = BuildPerService(analysis)
		case "per_destination":
			pols = BuildPerDestination(analysis)
		}
		gen := Generate(parsed.Policy, parsed, pols, prefix, strategies[i].Key)
		strategies[i].Policies = pols
		strategies[i].Config = gen.Config
		strategies[i].NewObjects = gen.NewObjects
		for _, gw := range gen.Warnings {
			if !containsString(warnings, gw) {
				warnings = append(warnings, gw)
			}
		}
	}
	markRecommended(strategies)

	respTuples := analysis.Tuples
	if len(respTuples) > maxTuplesInResponse {
		respTuples = respTuples[:maxTuplesInResponse]
	}

	e.log(r, "PolSplit Analyze", fmt.Sprintf("Analyzed policy %d of firewall %d (%d tuples, %d messages)",
		req.PolicyID, req.FwID, len(analysis.Tuples), totalMessages))
	e.writeJSON(w, map[string]any{
		"firewall":       FirewallRef{ID: req.FwID, FQDN: fqdn},
		"policy":         parsed.Policy,
		"action_display": displayAction(parsed.Policy.Action),
		"backup_time":    ts.In(e.tz).Format("2006-01-02 15:04"),
		"total_messages": totalMessages,
		"tuple_count":    len(analysis.Tuples),
		"tuples":         respTuples,
		"strategies":     strategies,
		"warnings":       warnings,
	})
}

// markRecommended flags the strategy with the lowest score: policy count
// first, then the number of objects that must be created. Ties favour
// per-service (the more idiomatic FortiGate layout).
func markRecommended(strategies []Strategy) {
	best := -1
	for i, s := range strategies {
		if len(s.Policies) == 0 {
			continue
		}
		if best == -1 {
			best = i
			continue
		}
		bestStrat := strategies[best]
		if len(s.Policies) < len(bestStrat.Policies) {
			best = i
		} else if len(s.Policies) == len(bestStrat.Policies) {
			if len(s.NewObjects) < len(bestStrat.NewObjects) {
				best = i
			}
		}
	}
	if best >= 0 {
		strategies[best].Recommended = true
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
