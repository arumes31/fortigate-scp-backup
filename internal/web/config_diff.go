package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/database"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
	appsecurity "github.com/arumes31/fortigate-scp-backup/internal/security"
	"github.com/go-chi/chi/v5"
)

const (
	configDiffMaxDiskBytes  = 4 << 20
	configDiffMaxPlainBytes = 2 << 20
	configDiffMaxLines      = 2000
	configDiffMaxWork       = 4_000_000
)

type configDiffRow struct {
	Kind      string
	LeftLine  int
	RightLine int
	Left      string
	Right     string
}

type backupCompareData struct {
	Base      BaseData
	Firewall  models.Firewall
	Left      models.Backup
	Right     models.Backup
	Rows      []configDiffRow
	Truncated bool
	Error     string
}

func parseBackupCompareIDs(r *http.Request) ([2]int, error) {
	values := r.URL.Query()["backup"]
	if len(values) != 2 {
		return [2]int{}, errors.New("select exactly two backups")
	}
	var ids [2]int
	for index, value := range values {
		id, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || id <= 0 {
			return [2]int{}, errors.New("invalid backup selection")
		}
		ids[index] = id
	}
	if ids[0] == ids[1] {
		return [2]int{}, errors.New("select two different backups")
	}
	return ids, nil
}

func selectComparisonBackups(backups []models.Backup, fwID int, ids [2]int) (models.Backup, models.Backup, error) {
	found := make(map[int]models.Backup, 2)
	for _, backup := range backups {
		if backup.FwID == fwID && (backup.ID == ids[0] || backup.ID == ids[1]) {
			found[backup.ID] = backup
		}
	}
	left, leftOK := found[ids[0]]
	right, rightOK := found[ids[1]]
	if !leftOK || !rightOK {
		return models.Backup{}, models.Backup{}, errors.New("selected backup does not belong to this firewall")
	}
	return left, right, nil
}

func (s *Server) readComparisonBackup(backup models.Backup) ([]string, bool, error) {
	path, err := appsecurity.JoinWithin(s.cfg.BackupDir, backup.Filename)
	if err != nil {
		return nil, false, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	if info.Size() > configDiffMaxDiskBytes {
		return nil, false, errors.New("encrypted backup exceeds comparison limit")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	plain, err := s.cipher.Decrypt(raw)
	if err != nil {
		return nil, false, err
	}
	truncated := len(plain) > configDiffMaxPlainBytes
	if truncated {
		plain = plain[:configDiffMaxPlainBytes]
	}
	plain = bytes.ReplaceAll(plain, []byte("\r\n"), []byte("\n"))
	lines := strings.Split(string(plain), "\n")
	if len(lines) > configDiffMaxLines {
		lines = lines[:configDiffMaxLines]
		truncated = true
	}
	return lines, truncated, nil
}

func configSideBySideDiff(left, right []string) ([]configDiffRow, error) {
	if len(left)*len(right) > configDiffMaxWork {
		return nil, errors.New("comparison work limit exceeded")
	}
	width := len(right) + 1
	lcs := make([]uint16, (len(left)+1)*width)
	for leftIndex := len(left) - 1; leftIndex >= 0; leftIndex-- {
		for rightIndex := len(right) - 1; rightIndex >= 0; rightIndex-- {
			cell := leftIndex*width + rightIndex
			if left[leftIndex] == right[rightIndex] {
				lcs[cell] = lcs[(leftIndex+1)*width+rightIndex+1] + 1
			} else {
				lcs[cell] = max(lcs[(leftIndex+1)*width+rightIndex], lcs[leftIndex*width+rightIndex+1])
			}
		}
	}
	rows := make([]configDiffRow, 0, len(left)+len(right))
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) || rightIndex < len(right) {
		switch {
		case leftIndex < len(left) && rightIndex < len(right) && left[leftIndex] == right[rightIndex]:
			rows = append(rows, configDiffRow{Kind: "unchanged", LeftLine: leftIndex + 1, RightLine: rightIndex + 1, Left: left[leftIndex], Right: right[rightIndex]})
			leftIndex++
			rightIndex++
		case rightIndex < len(right) && (leftIndex == len(left) || lcs[leftIndex*width+rightIndex+1] > lcs[(leftIndex+1)*width+rightIndex]):
			rows = append(rows, configDiffRow{Kind: "added", RightLine: rightIndex + 1, Right: right[rightIndex]})
			rightIndex++
		default:
			rows = append(rows, configDiffRow{Kind: "removed", LeftLine: leftIndex + 1, Left: left[leftIndex]})
			leftIndex++
		}
	}
	return rows, nil
}

func (s *Server) handleBackupCompare(w http.ResponseWriter, r *http.Request) {
	fwID, err := strconv.Atoi(chi.URLParam(r, "fwID"))
	if err != nil || fwID <= 0 {
		http.NotFound(w, r)
		return
	}
	ids, err := parseBackupCompareIDs(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	firewall, err := s.store.GetFirewall(r.Context(), fwID)
	if errors.Is(err, database.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Unable to load firewall", http.StatusInternalServerError)
		return
	}
	backups, err := s.store.ListBackups(r.Context(), fwID)
	if err != nil {
		http.Error(w, "Unable to load backups", http.StatusInternalServerError)
		return
	}
	left, right, err := selectComparisonBackups(backups, fwID, ids)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	leftLines, leftTruncated, err := s.readComparisonBackup(left)
	if err != nil {
		s.logger.Error("backup comparison read failed", "fw_id", fwID, "backup_id", left.ID, "error_type", fmt.Sprintf("%T", err))
		http.Error(w, "Unable to read selected backup", http.StatusUnprocessableEntity)
		return
	}
	rightLines, rightTruncated, err := s.readComparisonBackup(right)
	if err != nil {
		s.logger.Error("backup comparison read failed", "fw_id", fwID, "backup_id", right.ID, "error_type", fmt.Sprintf("%T", err))
		http.Error(w, "Unable to read selected backup", http.StatusUnprocessableEntity)
		return
	}
	rows, err := configSideBySideDiff(leftLines, rightLines)
	if err != nil {
		http.Error(w, "Backup comparison exceeds the work limit", http.StatusRequestEntityTooLarge)
		return
	}
	truncated := leftTruncated || rightTruncated
	actor := s.sess.User(r).Username
	s.store.LogActivity(actor, "Compare Backups", fmt.Sprintf("fw_id=%d backup_ids=%d,%d rows=%d truncated=%t", fwID, left.ID, right.ID, len(rows), truncated))
	s.logger.InfoContext(r.Context(), "backup comparison rendered", "fw_id", fwID, "left_backup_id", left.ID, "right_backup_id", right.ID, "rows", len(rows), "truncated", truncated)
	s.render(w, "backup_compare.html", backupCompareData{
		Base: s.base(r, "Compare backups · "+firewall.FQDN, "firewalls"), Firewall: *firewall,
		Left: left, Right: right, Rows: rows, Truncated: truncated,
	})
}
