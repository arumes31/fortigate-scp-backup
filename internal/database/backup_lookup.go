package database

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

// GetBackupByFilename reads the exact committed backup using the existing
// unique (fw_id, filename) index. It never scans the retention catalog or falls
// back to a newer backup. Missing/pruned rows return ErrNotFound.
func (s *Store) GetBackupByFilename(ctx context.Context, fwID int, filename string) (models.Backup, error) {
	var b models.Backup
	err := s.pool.QueryRow(ctx, `SELECT id,fw_id,timestamp,filename,COALESCE(size_bytes,0),COALESCE(checksum,'')
 FROM backups WHERE fw_id=$1 AND filename=$2`, fwID, filename).
		Scan(&b.ID, &b.FwID, &b.Timestamp, &b.Filename, &b.SizeBytes, &b.Checksum)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Backup{}, ErrNotFound
	}
	if err != nil {
		return models.Backup{}, err
	}
	return b, nil
}
