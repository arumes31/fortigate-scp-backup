package fgt_confgen

import (
	"database/sql"
	"encoding/json"
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
		if err := rows.Scan(&name); err == nil {
			list = append(list, name)
		}
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

func (e *Extension) renameTemplateInDB(username, oldName, newName string) (int64, error) {
	res, err := e.db.Exec("UPDATE templates SET name = ? WHERE username = ? AND name = ?", newName, username, oldName)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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

func (e *Extension) shortenURLInDB(url, shortCode string) error {
	_, err := e.db.Exec("INSERT INTO short_urls (short_code, url) VALUES (?, ?)", shortCode, url)
	return err
}

func (e *Extension) getURLFromShortCode(shortCode string) (string, error) {
	var originalURL string
	err := e.db.QueryRow("SELECT url FROM short_urls WHERE short_code = ?", shortCode).Scan(&originalURL)
	return originalURL, err
}

func (e *Extension) deleteShortURLsByTemplate(templateURL string) {
	_, _ = e.db.Exec("DELETE FROM short_urls WHERE url LIKE ?", "%"+templateURL)
}
