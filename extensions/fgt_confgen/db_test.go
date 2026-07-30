package fgt_confgen

import (
	"database/sql"
	"errors"
	"testing"
)

// TestShortenURLCollisionClassification proves the typed-error path: a real
// short_urls.short_code violation through the modernc driver must classify as
// errShortCodeCollision (retryable), while the first insert succeeds.
func TestShortenURLCollisionClassification(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if err := InitDB(db); err != nil {
		t.Fatal(err)
	}
	e := &Extension{db: db}

	if err := e.shortenURLInDB("/fgt-confgen/get_template/a", "alice", "abc123"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err = e.shortenURLInDB("/fgt-confgen/get_template/b", "alice", "abc123")
	if !errors.Is(err, errShortCodeCollision) {
		t.Fatalf("duplicate short code not classified as collision: %v", err)
	}
}

// TestLastConfigSchemaVersioning verifies the stored ParsedConfig blob
// round-trips under the current schema and that a pre-versioning (raw
// ParsedConfig) or otherwise mismatched blob is rejected instead of being
// partially decoded into wrong UI prefill data.
func TestLastConfigSchemaVersioning(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if err := InitDB(db); err != nil {
		t.Fatal(err)
	}
	e := &Extension{db: db}

	saved := ParsedConfig{Interfaces: []string{"wan1", "lan"}, Addresses: []string{"net-office"}}
	if err := e.saveLastConfigToDB("alice", saved); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := e.getLastConfigFromDB("alice")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Interfaces) != 2 || got.Interfaces[0] != "wan1" || len(got.Addresses) != 1 {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// A legacy row (raw ParsedConfig JSON, no schema wrapper) decodes with
	// Schema 0 and must be discarded.
	if _, err := db.Exec(`INSERT INTO last_config (username, config_data) VALUES ('bob', ?)`,
		`{"interfaces":["wan1"],"addresses":[]}`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.getLastConfigFromDB("bob"); err == nil {
		t.Error("legacy unversioned blob must be rejected")
	}
}

// TestShortURLOwnerScoping: deleting or renaming one owner's template must
// not touch another owner's short URLs for a same-named template. A legacy
// row without an owner (owner = ”) is keyed only by URL and cannot be
// attributed, so owner-scoped mutations must leave it strictly intact —
// neither deleted nor rewritten by another user's operation.
func TestShortURLOwnerScoping(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if err := InitDB(db); err != nil {
		t.Fatal(err)
	}
	e := &Extension{db: db}

	const urlWeb = "/fgt-confgen/get_template/web"
	if err := e.shortenURLInDB(urlWeb, "alice", "aaa111"); err != nil {
		t.Fatal(err)
	}
	if err := e.shortenURLInDB(urlWeb, "bob", "bbb222"); err != nil {
		t.Fatal(err)
	}
	// Legacy row from before the owner column existed (owner = '').
	if err := e.shortenURLInDB(urlWeb, "", "leg000"); err != nil {
		t.Fatal(err)
	}

	// Bob deletes his "web": Alice's link and the legacy link must survive.
	e.deleteShortURLsByTemplate("bob", urlWeb)
	if got, err := e.getURLFromShortCode("aaa111"); err != nil || got != urlWeb {
		t.Fatalf("alice's short URL lost: %q, %v", got, err)
	}
	if _, err := e.getURLFromShortCode("bbb222"); err != sql.ErrNoRows {
		t.Fatalf("bob's short URL must be deleted, got err=%v", err)
	}
	if got, err := e.getURLFromShortCode("leg000"); err != nil || got != urlWeb {
		t.Fatalf("legacy ownerless URL must survive bob's delete: %q, %v", got, err)
	}

	// Alice renames "web" → "web2": only her rows rewrite; bob's and the
	// legacy ownerless row stay untouched.
	if err := e.shortenURLInDB(urlWeb, "bob", "bbb333"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec("INSERT INTO templates (username, name, data) VALUES ('alice', 'web', '{}')"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.renameTemplateInDB("alice", "web", "web2", urlWeb, "/fgt-confgen/get_template/web2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.getURLFromShortCode("aaa111"); got != "/fgt-confgen/get_template/web2" {
		t.Fatalf("alice's short URL not rewritten: %q", got)
	}
	if got, _ := e.getURLFromShortCode("bbb333"); got != urlWeb {
		t.Fatalf("bob's short URL must be untouched by alice's rename: %q", got)
	}
	if got, _ := e.getURLFromShortCode("leg000"); got != urlWeb {
		t.Fatalf("legacy ownerless URL must not be rewritten by alice's rename: %q", got)
	}
}
