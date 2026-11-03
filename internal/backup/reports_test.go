package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

type reportFixtureStore struct {
	refs    []models.FirewallRef
	backups map[int][]models.Backup
	err     error
}

func (s reportFixtureStore) ListFirewallRefs(ctx context.Context) ([]models.FirewallRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.refs, s.err
}
func (s reportFixtureStore) ListBackups(ctx context.Context, fwID int) ([]models.Backup, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.backups[fwID], s.err
}

func TestReportSourcesSelectLatestByTimestampThenID(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	store := reportFixtureStore{refs: []models.FirewallRef{{ID: 2, FQDN: "branch"}, {ID: 1, FQDN: "main"}, {ID: 3, FQDN: "empty"}}, backups: map[int][]models.Backup{
		1: {{ID: 2, FwID: 1, Timestamp: ts}, {ID: 6, FwID: 1, Timestamp: ts}, {ID: 99, FwID: 2, Timestamp: ts.Add(time.Hour)}},
		2: {{ID: 50, FwID: 2, Timestamp: ts.Add(-time.Hour)}, {ID: 3, FwID: 2, Timestamp: ts}},
	}}
	sources, err := NewReportSources(store, t.TempDir(), nil).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].FirewallID != 1 || sources[0].BackupID != 6 || sources[1].FirewallID != 2 || sources[1].BackupID != 3 {
		t.Fatalf("latest source selection = %+v", sources)
	}
}

func newReportReadFixture(t *testing.T) (*ReportSources, reportFixtureStore, []byte) {
	t.Helper()
	plain := []byte("#config-version=FGT-7.4.7-build2731\nconfig system global\n set hostname test\nend\n")
	sum := sha256.Sum256(plain)
	cipher, err := crypto.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cipher.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1", "source.conf"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store := reportFixtureStore{refs: []models.FirewallRef{{ID: 1, FQDN: "firewall.example"}, {ID: 2, FQDN: "other.example"}}, backups: map[int][]models.Backup{
		1: {{ID: 8, FwID: 1, Filename: "1/pruned-newer.conf", Timestamp: time.Now()},
			{ID: 7, FwID: 1, Filename: "1/source.conf", Timestamp: time.Unix(1, 0), SizeBytes: int64(len(plain)), Checksum: hex.EncodeToString(sum[:])}},
	}}
	return NewReportSources(store, dir, cipher), store, plain
}

func TestReadReportSourcePinsRequestedBackupAndAuthenticates(t *testing.T) {
	t.Parallel()
	reader, store, plain := newReportReadFixture(t)
	source, got, err := reader.Read(context.Background(), 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) || source.BackupID != 7 || source.FirewallID != 1 || source.Checksum != store.backups[1][1].Checksum {
		t.Fatalf("source was not pinned: %+v %q", source, got)
	}
	if _, _, err := reader.Read(context.Background(), 1, 8); err == nil {
		t.Fatal("pruned source silently substituted")
	}
	if _, _, err := reader.Read(context.Background(), 2, 7); err == nil {
		t.Fatal("cross-firewall backup accepted")
	}
}

func TestReadReportSourceRejectsInvalidEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *ReportSources, reportFixtureStore)
	}{
		{"checksum", func(t *testing.T, r *ReportSources, s reportFixtureStore) { s.backups[1][1].Checksum = "bad" }},
		{"size", func(t *testing.T, r *ReportSources, s reportFixtureStore) { s.backups[1][1].SizeBytes = 1 }},
		{"traversal", func(t *testing.T, r *ReportSources, s reportFixtureStore) {
			s.backups[1][1].Filename = "1/../../outside.conf"
		}},
		{"wrong directory", func(t *testing.T, r *ReportSources, s reportFixtureStore) { s.backups[1][1].Filename = "2/source.conf" }},
		{"plaintext", func(t *testing.T, r *ReportSources, s reportFixtureStore) {
			if err := os.WriteFile(filepath.Join(r.dir, "1/source.conf"), []byte("plain"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"tampered ciphertext", func(t *testing.T, r *ReportSources, s reportFixtureStore) {
			p := filepath.Join(r.dir, "1/source.conf")
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)-1] ^= 1
			if err := os.WriteFile(p, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"too large", func(t *testing.T, r *ReportSources, s reportFixtureStore) {
			s.backups[1][1].SizeBytes = ReportMaxConfigBytes + 1
		}},
		{"oversized disk file", func(t *testing.T, r *ReportSources, s reportFixtureStore) {
			if err := os.Truncate(filepath.Join(r.dir, "1/source.conf"), ReportMaxConfigBytes+1025); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink escape", func(t *testing.T, r *ReportSources, s reportFixtureStore) {
			target := filepath.Join(t.TempDir(), "private.conf")
			if err := os.WriteFile(target, []byte("private"), 0o600); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(r.dir, "1/source.conf")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Skip(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, store, _ := newReportReadFixture(t)
			test.mutate(t, reader, store)
			if _, plain, err := reader.Read(context.Background(), 1, 7); err == nil || plain != nil {
				t.Fatalf("invalid source returned content: err=%v", err)
			}
		})
	}
}

func TestReportReaderLegacyChecksumAndCancellation(t *testing.T) {
	t.Parallel()
	reader, store, plain := newReportReadFixture(t)
	store.backups[1][1].Checksum = ""
	store.backups[1][1].SizeBytes = 0
	source, got, err := reader.Read(context.Background(), 1, 7)
	if err != nil || len(source.Checksum) != 64 || !bytes.Equal(got, plain) {
		t.Fatalf("legacy source=(%+v,%v)", source, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := reader.Read(ctx, 1, 7); !errors.Is(err, context.Canceled) {
		t.Fatalf("read cancellation = %v", err)
	}
	if _, err := reader.List(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("list cancellation = %v", err)
	}
}

func TestCommittedBackupObserversDoNotReplaceStatusHook(t *testing.T) {
	t.Parallel()
	s := &Service{logger: slog.New(slog.DiscardHandler)}
	var statuses []string
	s.SetStatusHook(func(_ int, status string) { statuses = append(statuses, status) })
	var received []models.Backup
	s.SubscribeBackup(nil)
	s.SubscribeBackup(func(models.Backup) { panic("extension failure") })
	s.SubscribeBackup(func(b models.Backup) { received = append(received, b) })
	s.emit(5, "In Progress")
	s.emit(5, "Failed")
	s.emit(5, "Success")
	if len(received) != 0 {
		t.Fatal("status event was mistaken for a committed snapshot")
	}
	s.notifyCommitted(models.Backup{})
	if len(received) != 0 {
		t.Fatal("uncommitted metadata was emitted")
	}
	b := models.Backup{ID: 9, FwID: 5, Filename: "5/source.conf", Checksum: "checksum"}
	s.notifyCommitted(b)
	if !reflect.DeepEqual(received, []models.Backup{b}) {
		t.Fatalf("committed observers = %+v", received)
	}
	if !reflect.DeepEqual(statuses, []string{"In Progress", "Failed", "Success"}) {
		t.Fatalf("status hook changed: %v", statuses)
	}
}

type committedLookupFunc func(context.Context, int, string) (models.Backup, error)

func (f committedLookupFunc) GetBackupByFilename(ctx context.Context, id int, filename string) (models.Backup, error) {
	return f(ctx, id, filename)
}

func TestCommittedNotificationUsesBoundedExactLookup(t *testing.T) {
	t.Parallel()
	want := models.Backup{ID: 9, FwID: 5, Filename: "5/source.conf", Checksum: "expected"}
	for _, tc := range []struct {
		name             string
		row              models.Backup
		err              error
		wantNotification bool
	}{
		{name: "exact row", row: want, wantNotification: true},
		{name: "catalog unavailable", err: errors.New("catalog unavailable")},
		{name: "wrong firewall", row: models.Backup{ID: 9, FwID: 6, Filename: want.Filename, Checksum: want.Checksum}},
		{name: "wrong filename", row: models.Backup{ID: 9, FwID: 5, Filename: "5/newer.conf", Checksum: want.Checksum}},
		{name: "different contents", row: models.Backup{ID: 9, FwID: 5, Filename: want.Filename, Checksum: "other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{logger: slog.New(slog.DiscardHandler)}
			lookups := 0
			s.committedGetter = committedLookupFunc(func(ctx context.Context, fwID int, filename string) (models.Backup, error) {
				lookups++
				if fwID != want.FwID || filename != want.Filename {
					t.Fatalf("lookup of different source: %d %s", fwID, filename)
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > committedLookupTimeout {
					t.Fatalf("missing short lookup deadline: %v %v", deadline, ok)
				}
				return tc.row, tc.err
			})
			var statuses []string
			s.SetStatusHook(func(_ int, status string) { statuses = append(statuses, status) })
			s.emit(want.FwID, "Success")
			s.publishCommitted(want.FwID, want.Filename, want.Checksum)
			if lookups != 0 {
				t.Fatal("optional source lookup ran without observers")
			}
			var got []models.Backup
			s.SubscribeBackup(func(b models.Backup) { got = append(got, b) })
			s.publishCommitted(want.FwID, want.Filename, want.Checksum)
			if lookups != 1 || (len(got) == 1) != tc.wantNotification {
				t.Fatalf("lookup=%d notifications=%v", lookups, got)
			}
			if len(got) > 0 && got[0] != want {
				t.Fatalf("event references a different source: %+v", got[0])
			}
			if !reflect.DeepEqual(statuses, []string{"Success"}) {
				t.Fatalf("optional lookup changed successful backup status: %v", statuses)
			}
		})
	}
}

func TestCommittedNotificationWithoutLookupCapability(t *testing.T) {
	t.Parallel()
	s := &Service{logger: slog.New(slog.DiscardHandler)}
	s.SubscribeBackup(func(models.Backup) { t.Fatal("notification without exact-row lookup") })
	s.publishCommitted(1, "1/source.conf", "checksum")
}
