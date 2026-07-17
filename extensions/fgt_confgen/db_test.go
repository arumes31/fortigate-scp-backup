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

	if err := e.shortenURLInDB("/fgt-confgen/get_template/a", "abc123"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err = e.shortenURLInDB("/fgt-confgen/get_template/b", "abc123")
	if !errors.Is(err, errShortCodeCollision) {
		t.Fatalf("duplicate short code not classified as collision: %v", err)
	}
}
