package fgt_confconv

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

// FirewallRef represents a reference to a firewall in the main database.
type FirewallRef struct {
	ID   int    `json:"id"`
	FQDN string `json:"fqdn"`
}

func (e *Extension) index(w http.ResponseWriter, r *http.Request) {
	firewalls, err := e.fetchFirewalls(r.Context())
	if err != nil {
		e.logger.Error("confconv: failed to fetch firewalls", "err", err)
	}
	data := struct {
		Base      baseData
		Firewalls []FirewallRef
	}{
		Base:      e.baseData(r, "Configuration Conversions", "confconv"),
		Firewalls: firewalls,
	}
	if err := e.tmpl.ExecuteTemplate(w, "fgt_confconv_index.html", data); err != nil {
		e.logger.Error("confconv: template render failed", "err", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (e *Extension) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (e *Extension) jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
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

// loadBackup returns the firewall's latest decrypted config backup.
func (e *Extension) loadBackup(ctx context.Context, fwID int) (content string, ts time.Time, err error) {
	var exists int
	if err = e.pgPool.QueryRow(ctx, `SELECT 1 FROM firewalls WHERE id = $1`, fwID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ts, fmt.Errorf("firewall %d: %w", fwID, ErrNotFound)
		}
		return "", ts, err
	}
	var filename string
	err = e.pgPool.QueryRow(ctx,
		"SELECT filename, timestamp FROM backups WHERE fw_id = $1 ORDER BY timestamp DESC LIMIT 1", fwID).Scan(&filename, &ts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ts, fmt.Errorf("backups for firewall %d: %w", fwID, ErrNotFound)
		}
		return "", ts, err
	}
	diskPath := filepath.Join(e.cfg.BackupDir, filepath.FromSlash(filename))
	encData, err := os.ReadFile(diskPath)
	if err != nil {
		e.logger.Error("confconv: failed to read backup file", "path", diskPath, "err", err)
		return "", ts, errors.New("failed to read backup file from disk")
	}
	cipher, err := crypto.New(e.cfg.EncryptionKey)
	if err != nil {
		return "", ts, errors.New("failed to init cipher")
	}
	plain, err := cipher.Decrypt(encData)
	if err != nil {
		e.logger.Error("confconv: failed to decrypt backup", "path", diskPath, "err", err)
		return "", ts, errors.New("failed to decrypt backup")
	}
	return string(plain), ts, nil
}

// configSummaryResponse is the parsed-config projection the UI uses to
// populate its recipe option forms (interface/zone/SD-WAN/route pick-lists).
type configSummaryResponse struct {
	Version      string            `json:"version"`
	VersionOK    bool              `json:"versionOK"`
	Interfaces   []*InterfaceEntry `json:"interfaces"`
	Zones        []*ZoneEntry      `json:"zones"`
	SDWANZones   []*SDWANZone      `json:"sdwanZones"`
	SDWANMembers []*SDWANMember    `json:"sdwanMembers"`
	StaticRoutes []*RouteEntry     `json:"staticRoutes"`
	BackupTime   string            `json:"backupTime"`
}

func (e *Extension) configSummary(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(r.URL.Query().Get("fw_id"))
	if err != nil {
		e.jsonError(w, http.StatusBadRequest, "invalid fw_id")
		return
	}
	content, ts, err := e.loadBackup(r.Context(), fwID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			e.jsonError(w, http.StatusNotFound, err.Error())
			return
		}
		e.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	cfg := ParseConfig(content)
	resp := configSummaryResponse{
		Version:      cfg.Version.String(),
		VersionOK:    cfg.Version.SupportsSDWANSyntax(),
		SDWANMembers: cfg.SDWANMembers,
		StaticRoutes: cfg.StaticRoutes,
		BackupTime:   ts.UTC().Format(time.RFC3339),
	}
	for _, iface := range cfg.Interfaces {
		resp.Interfaces = append(resp.Interfaces, iface)
	}
	for _, z := range cfg.Zones {
		resp.Zones = append(resp.Zones, z)
	}
	for _, z := range cfg.SDWANZones {
		resp.SDWANZones = append(resp.SDWANZones, z)
	}
	e.writeJSON(w, resp)
}

// convertRequest is the body of POST /convert.
type convertRequest struct {
	FwID    int               `json:"fw_id"`
	Recipes []RecipeSelection `json:"recipes"`
}

func (e *Extension) convert(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, e.cfg.CSVMaxBytes)
	var req convertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		e.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Recipes) == 0 {
		e.jsonError(w, http.StatusBadRequest, "select at least one recipe")
		return
	}

	content, _, err := e.loadBackup(r.Context(), req.FwID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			e.jsonError(w, http.StatusNotFound, err.Error())
			return
		}
		e.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	cfg := ParseConfig(content)
	// Version support is enforced per recipe now (only the SD-WAN recipes need
	// 7.4+); FortiLink and zone conversions run on older trains too, so the
	// pipeline gates each recipe via its Applicable() check.
	result, err := RunPipeline(cfg, req.Recipes)
	if err != nil {
		var pe *PipelineError
		if errors.As(err, &pe) {
			e.jsonError(w, http.StatusBadRequest, pe.Error())
			return
		}
		e.logger.Error("confconv: pipeline failed", "err", err)
		e.jsonError(w, http.StatusInternalServerError, "internal error running the pipeline")
		return
	}

	e.log(r, "confconv_convert", fmt.Sprintf("fw_id=%d recipes=%v", req.FwID, result.AppliedOrder))
	e.writeJSON(w, result)
}
