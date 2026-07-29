package web

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestEnsureCVEDefsSchema verifies that a storage-shape change wipes every
// stored CVE row (live and seed) exactly once: old-shape rows would decode to
// zero values and silently disable CVE matching — permanently on offline
// installs, whose seed rows are only written when the table is empty.
func TestEnsureCVEDefsSchema(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "insights.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE cve_cache (id TEXT PRIMARY KEY, summary_en TEXT NOT NULL, severity TEXT NOT NULL,
			ranges_json TEXT NOT NULL, remediation TEXT NOT NULL, source TEXT NOT NULL)`,
		`CREATE TABLE cve_meta (id INTEGER PRIMARY KEY CHECK (id = 1), last_success_at TEXT,
			last_attempt_at TEXT, last_error TEXT, defs_schema INTEGER NOT NULL DEFAULT 0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// Old-shape rows from before versioning existed (defs_schema defaults 0).
	if _, err := db.Exec(`INSERT INTO cve_cache VALUES
		('CVE-OLD-1', 's', 'critical', '{"legacy":"shape"}', 'r', 'fallback-seed'),
		('CVE-OLD-2', 's', 'high', '{"legacy":"shape"}', 'r', 'live')`); err != nil {
		t.Fatal(err)
	}

	ensureCVEDefsSchema(db)
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM cve_cache").Scan(&count); err != nil || count != 0 {
		t.Fatalf("old-shape rows remaining = %d (err %v), want 0", count, err)
	}
	var stored int
	if err := db.QueryRow("SELECT defs_schema FROM cve_meta WHERE id = 1").Scan(&stored); err != nil || stored != cveDefsSchema {
		t.Fatalf("defs_schema = %d (err %v), want %d", stored, err, cveDefsSchema)
	}

	// Same schema: a second run must be a no-op and keep current rows.
	if _, err := db.Exec(`INSERT INTO cve_cache VALUES
		('CVE-NEW-1', 's', 'high', ?, 'r', 'live')`, encodeRanges(nil)); err != nil {
		t.Fatal(err)
	}
	ensureCVEDefsSchema(db)
	if err := db.QueryRow("SELECT COUNT(*) FROM cve_cache").Scan(&count); err != nil || count != 1 {
		t.Fatalf("current-shape row lost: count = %d (err %v), want 1", count, err)
	}
}
