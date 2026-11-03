package reportlogs

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
	_ "modernc.org/sqlite" // Read-only access to the existing source mapping DB.
)

func (c *Collector) sources(ctx context.Context, source reportmodel.Source, a reportmodel.Assessment) ([]string, error) {
	hosts, err := c.mappedSources(ctx, source.Firewall)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		fallback := a.Hostname
		if fallback == "" {
			fallback = shortHostname(source.Firewall)
		}
		hosts = []string{fallback}
	}
	if len(hosts) > 16 {
		return nil, errors.New("graylog source mapping exceeds the supported source count")
	}
	unique := map[string]bool{}
	result := []string{}
	for _, host := range hosts {
		if !validIdentity(host) {
			return nil, errors.New("graylog source identity is missing or invalid")
		}
		if !unique[host] {
			result = append(result, host)
			unique[host] = true
		}
	}
	sort.Strings(result)
	return result, nil
}

func (c *Collector) mappedSources(ctx context.Context, fqdn string) ([]string, error) {
	if c.dataDir == "" {
		return nil, nil
	}
	path := filepath.Join(c.dataDir, "fgt-adm-vpn-conf-db.db")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errors.New("graylog source mapping could not be read")
	}
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	u.RawQuery = "mode=ro"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, errors.New("graylog source mapping could not be opened")
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	queries := []struct {
		sql  string
		args []any
	}{
		{`SELECT COALESCE(firewallname,''), COALESCE(cluster_hostnames,'') FROM vpn_config WHERE lower(dns_name_full)=lower(?) LIMIT 2`, []any{fqdn}},
		{`SELECT COALESCE(firewallname,''), COALESCE(cluster_hostnames,'') FROM vpn_config WHERE lower(firewallname)=lower(?) OR lower(dns_name)=lower(?) LIMIT 2`, []any{fqdn, fqdn}},
	}
	if short := shortHostname(fqdn); short != fqdn {
		queries = append(queries, struct {
			sql  string
			args []any
		}{`SELECT COALESCE(firewallname,''), COALESCE(cluster_hostnames,'') FROM vpn_config WHERE lower(firewallname)=lower(?) OR lower(dns_name)=lower(?) OR lower(dns_name_full)=lower(?) LIMIT 2`, []any{short, short, short}})
	}
	for _, query := range queries {
		rows, err := db.QueryContext(ctx, query.sql, query.args...)
		if err != nil {
			return nil, errors.New("graylog source mapping lookup failed")
		}
		matches := 0
		var name, cluster string
		for rows.Next() {
			if err = rows.Scan(&name, &cluster); err != nil {
				break
			}
			matches++
		}
		readErr := rows.Err()
		_ = rows.Close()
		if err != nil || readErr != nil {
			return nil, errors.New("graylog source mapping lookup failed")
		}
		if matches > 1 {
			return nil, errors.New("graylog source mapping is ambiguous; collection was not widened")
		}
		if matches == 1 {
			if len(cluster) > 16*257 || len(name) > 256 {
				return nil, errors.New("graylog source mapping exceeds the supported identity size")
			}
			var hosts []string
			for _, host := range strings.Split(cluster, ",") {
				if host = strings.TrimSpace(host); host != "" {
					hosts = append(hosts, host)
				}
			}
			if len(hosts) > 0 {
				return hosts, nil
			}
			if name != "" {
				return []string{name}, nil
			}
			return nil, errors.New("graylog source mapping contains no usable identity")
		}
	}
	return nil, nil
}

func shortHostname(fqdn string) string {
	if dot := strings.IndexByte(fqdn, '.'); dot > 0 {
		return fqdn[:dot]
	}
	return fqdn
}

func validIdentity(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

func scopeQuery(sources, vdoms []string, window timeWindow) string {
	parts := make([]string, 0, len(sources))
	for _, source := range sources {
		parts = append(parts, `source:"`+escaped(source)+`"`)
	}
	query := "(" + strings.Join(parts, " OR ") + ")"
	if len(vdoms) > 0 {
		parts = parts[:0]
		for _, vdom := range vdoms {
			parts = append(parts, `vd:"`+escaped(vdom)+`"`)
		}
		query += " AND (" + strings.Join(parts, " OR ") + ")"
	}
	return query + " AND " + halfOpenWindow(window.start, window.end)
}
