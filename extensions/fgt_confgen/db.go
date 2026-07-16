package fgt_confgen

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// InitDB initializes SQLite schema.
func InitDB(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS templates (
		username TEXT NOT NULL,
		name TEXT NOT NULL,
		data TEXT NOT NULL,
		PRIMARY KEY (username, name)
	)`); err != nil {
		return err
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS last_config (
		username TEXT PRIMARY KEY,
		config_data TEXT NOT NULL
	)`); err != nil {
		return err
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS short_urls (
		short_code TEXT PRIMARY KEY,
		url TEXT NOT NULL
	)`); err != nil {
		return err
	}

	return nil
}

func (e *Extension) getTemplateNames(username string) ([]string, error) {
	rows, err := e.db.Query("SELECT DISTINCT name FROM templates WHERE username = ? OR username = '__global__' ORDER BY name", username)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var list []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		list = append(list, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

func (e *Extension) getTemplateFromDB(username, name string) (string, string, error) {
	var dataJSON string
	var owner string
	err := e.db.QueryRow("SELECT data, username FROM templates WHERE (username = ? OR username = '__global__') AND name = ? ORDER BY (CASE WHEN username = ? THEN 0 ELSE 1 END) LIMIT 1",
		username, name, username).Scan(&dataJSON, &owner)
	if err != nil {
		return "", "", err
	}
	return dataJSON, owner, nil
}

func (e *Extension) saveTemplateToDB(username, name, dataJSON string) error {
	_, err := e.db.Exec("INSERT INTO templates (username, name, data) VALUES (?, ?, ?) ON CONFLICT(username, name) DO UPDATE SET data = excluded.data",
		username, name, dataJSON)
	return err
}

func (e *Extension) deleteTemplateFromDB(username, name string) (int64, error) {
	res, err := e.db.Exec("DELETE FROM templates WHERE username = ? AND name = ?", username, name)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// renameTemplateInDB renames a template and rewrites its associated short
// URLs in one transaction, so a failure in either statement leaves both
// tables unchanged. The LIKE filter is wildcard-escaped because template
// names may legitimately contain % or _.
func (e *Extension) renameTemplateInDB(username, oldName, newName, oldURL, newURL string) (int64, error) {
	tx, err := e.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec("UPDATE templates SET name = ? WHERE username = ? AND name = ?", newName, username, oldName)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if affected > 0 {
		// Stored URLs may carry a scheme+host prefix, so match on the exact
		// template path as an escaped suffix and substitute it in place.
		if _, err := tx.Exec("UPDATE short_urls SET url = REPLACE(url, ?, ?) WHERE url LIKE ? ESCAPE '\\'",
			oldURL, newURL, "%"+escapeLike(oldURL)); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return affected, nil
}

func (e *Extension) saveLastConfigToDB(username string, config ParsedConfig) error {
	parsedJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}
	_, err = e.db.Exec("INSERT INTO last_config (username, config_data) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET config_data = excluded.config_data",
		username, string(parsedJSON))
	return err
}

func (e *Extension) getLastConfigFromDB(username string) (ParsedConfig, error) {
	var config ParsedConfig
	var lastConfJSON string
	err := e.db.QueryRow("SELECT config_data FROM last_config WHERE username = ?", username).Scan(&lastConfJSON)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal([]byte(lastConfJSON), &config)
	return config, err
}

// errShortCodeCollision reports an INSERT that failed only because the random
// short code already exists, so the caller can retry with a fresh code while
// treating every other database failure as fatal.
var errShortCodeCollision = errors.New("short code already exists")

func (e *Extension) shortenURLInDB(url, shortCode string) error {
	_, err := e.db.Exec("INSERT INTO short_urls (short_code, url) VALUES (?, ?)", shortCode, url)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("%w: %v", errShortCodeCollision, err)
	}
	return err
}

func (e *Extension) getURLFromShortCode(shortCode string) (string, error) {
	var originalURL string
	err := e.db.QueryRow("SELECT url FROM short_urls WHERE short_code = ?", shortCode).Scan(&originalURL)
	return originalURL, err
}

// escapeLike escapes %, _ and \ so a value can be embedded in a LIKE pattern
// with ESCAPE '\' without wildcard interpretation.
func escapeLike(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c == '%' || c == '_' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func (e *Extension) deleteShortURLsByTemplate(templateURL string) {
	_, _ = e.db.Exec("DELETE FROM short_urls WHERE url LIKE ? ESCAPE '\\'", "%"+escapeLike(templateURL))
}
