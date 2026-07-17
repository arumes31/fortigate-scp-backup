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

// TestShortURLOwnerScoping: deleting or renaming one owner's template must
// not touch another owner's short URLs for a same-named template; legacy
// rows without an owner keep the old URL-only matching.
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

	// Bob deletes his "web": Alice's link must survive.
	e.deleteShortURLsByTemplate("bob", urlWeb)
	if got, err := e.getURLFromShortCode("aaa111"); err != nil || got != urlWeb {
		t.Fatalf("alice's short URL lost: %q, %v", got, err)
	}
	if _, err := e.getURLFromShortCode("bbb222"); err != sql.ErrNoRows {
		t.Fatalf("bob's short URL must be deleted, got err=%v", err)
	}

	// Alice renames "web" → "web2": only her rows rewrite.
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
}
