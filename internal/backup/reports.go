package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
	appsecurity "github.com/arumes31/fortigate-scp-backup/internal/security"
)

// ReportMaxConfigBytes bounds decrypted source size without silently truncating
// the configuration. The encrypted envelope has a small additional allowance.
const ReportMaxConfigBytes = 16 << 20

// ReportSourceStore only exposes credential-free firewall and backup metadata.
type ReportSourceStore interface {
	ListFirewallRefs(context.Context) ([]models.FirewallRef, error)
	ListBackups(context.Context, int) ([]models.Backup, error)
}

// ReportSources provides immutable source selection for configuration reports.
// Authorization belongs to the host's protected routes; automated jobs use the
// same bounded reader without exposing SSH credentials to an extension.
type ReportSources struct {
	store  ReportSourceStore
	dir    string
	cipher *crypto.Cipher
}

func NewReportSources(store ReportSourceStore, dir string, cipher *crypto.Cipher) *ReportSources {
	return &ReportSources{store: store, dir: dir, cipher: cipher}
}

func reportSource(fw models.FirewallRef, b models.Backup) reportmodel.Source {
	return reportmodel.Source{FirewallID: fw.ID, Firewall: fw.FQDN,
		BackupID: b.ID, BackupAt: b.Timestamp, Checksum: b.Checksum}
}

// List returns one newest committed backup per firewall, with stable ordering.
// Equal timestamps are broken by row ID, independently of database row order.
func (r *ReportSources) List(ctx context.Context) ([]reportmodel.Source, error) {
	refs, err := r.store.ListFirewallRefs(ctx)
	if err != nil {
		return nil, err
	}
	var out []reportmodel.Source
	for _, fw := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rows, err := r.store.ListBackups(ctx, fw.ID)
		if err != nil {
			return nil, err
		}
		var latest models.Backup
		for _, b := range rows {
			if b.FwID != fw.ID || b.ID <= 0 {
				continue
			}
			if latest.ID == 0 || b.Timestamp.After(latest.Timestamp) ||
				(b.Timestamp.Equal(latest.Timestamp) && b.ID > latest.ID) {
				latest = b
			}
		}
		if latest.ID > 0 {
			out = append(out, reportSource(fw, latest))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirewallID < out[j].FirewallID })
	return out, nil
}

// Read verifies a particular backup ID belongs to the requested firewall and
// authenticates the entire encrypted file before returning its plaintext.
// A removed source is an error; another backup is never substituted.
func (r *ReportSources) Read(ctx context.Context, firewallID, backupID int) (reportmodel.Source, []byte, error) {
	var empty reportmodel.Source
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	if firewallID <= 0 || backupID <= 0 {
		return empty, nil, errors.New("invalid report source")
	}
	if r.cipher == nil || !r.cipher.Enabled() {
		return empty, nil, errors.New("report source encryption is required")
	}
	refs, err := r.store.ListFirewallRefs(ctx)
	if err != nil {
		return empty, nil, err
	}
	var fw models.FirewallRef
	for _, ref := range refs {
		if ref.ID == firewallID {
			fw = ref
			break
		}
	}
	if fw.ID == 0 {
		return empty, nil, errors.New("report firewall no longer exists")
	}
	rows, err := r.store.ListBackups(ctx, firewallID)
	if err != nil {
		return empty, nil, err
	}
	var selected models.Backup
	for _, b := range rows {
		if b.FwID == firewallID && b.ID == backupID {
			selected = b
			break
		}
	}
	if selected.ID == 0 {
		return empty, nil, errors.New("report backup does not belong to this firewall or was removed")
	}
	prefix := strconv.Itoa(firewallID) + "/"
	if !strings.HasPrefix(selected.Filename, prefix) {
		return empty, nil, errors.New("report source path does not belong to this firewall")
	}
	relative := strings.TrimPrefix(selected.Filename, prefix)
	firewallDir := filepath.Join(r.dir, strconv.Itoa(firewallID))
	if selected.SizeBytes > ReportMaxConfigBytes {
		return empty, nil, errors.New("configuration exceeds report size limit")
	}
	if _, err := appsecurity.JoinWithin(firewallDir, relative); err != nil {
		return empty, nil, errors.New("invalid report source path")
	}
	root, err := os.OpenRoot(firewallDir)
	if err != nil {
		return empty, nil, fmt.Errorf("open backup directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(relative)
	if err != nil {
		return empty, nil, fmt.Errorf("open selected backup: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return empty, nil, err
	}
	const maxDisk = ReportMaxConfigBytes + 1024
	if !info.Mode().IsRegular() || info.Size() > maxDisk {
		return empty, nil, errors.New("report source is not a bounded regular backup file")
	}
	raw, err := io.ReadAll(io.LimitReader(reportContextReader{ctx: ctx, r: file}, maxDisk+1))
	if err != nil {
		return empty, nil, err
	}
	if len(raw) > maxDisk {
		return empty, nil, errors.New("encrypted backup exceeds report size limit")
	}
	if !crypto.HasHeader(raw) {
		return empty, nil, errors.New("report source is not encrypted")
	}
	plain, err := r.cipher.Decrypt(raw)
	if err != nil {
		return empty, nil, errors.New("report source authentication failed")
	}
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	if len(plain) == 0 || len(plain) > ReportMaxConfigBytes {
		return empty, nil, errors.New("configuration is empty or exceeds report size limit")
	}
	if selected.SizeBytes > 0 && selected.SizeBytes != int64(len(plain)) {
		return empty, nil, errors.New("report source size mismatch")
	}
	sum := sha256.Sum256(plain)
	checksum := hex.EncodeToString(sum[:])
	if selected.Checksum != "" && !strings.EqualFold(selected.Checksum, checksum) {
		return empty, nil, errors.New("report source checksum mismatch")
	}
	source := reportSource(fw, selected)
	// Legacy rows may predate recorded checksums. Authenticate their encrypted
	// content and pin the calculated checksum in this assessment's provenance.
	source.Checksum = checksum
	return source, plain, nil
}

type reportContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r reportContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
