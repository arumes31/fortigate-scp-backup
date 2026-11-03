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

const (
	maxSourceIdentities = 16
	maxScopeQueryBytes  = 320 << 10
	maxMappingRows      = 10000
	maxMappingScanBytes = 4 << 20
)

type sourceResolution struct {
	hosts  []string
	origin string
	match  string
	rowID  int64
}

func (c *Collector) sources(ctx context.Context, source reportmodel.Source, a reportmodel.Assessment) (sourceResolution, error) {
	db, err := c.openSourceMapping()
	if err != nil {
		return sourceResolution{}, err
	}
	var tx *sql.Tx
	if db != nil {
		defer func() { _ = db.Close() }()
		// Resolve identities and check case-variant ownership in one snapshot,
		// so an ADM edit between the lookups cannot change the selected row.
		tx, err = db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return sourceResolution{}, errors.New("graylog source mapping could not be read")
		}
		defer func() { _ = tx.Rollback() }()
	}
	resolved, err := mappedSources(ctx, tx, source.Firewall)
	if err != nil {
		return sourceResolution{}, err
	}
	if len(resolved.hosts) == 0 {
		fallback := a.Hostname
		resolved.origin = "config_hostname"
		if fallback == "" {
			fallback = shortHostname(source.Firewall)
			resolved.origin = "registered_short_hostname"
		}
		resolved.hosts = []string{fallback}
	}
	if len(resolved.hosts) > maxSourceIdentities {
		return sourceResolution{}, errors.New("graylog source mapping exceeds the supported source count")
	}
	for _, host := range resolved.hosts {
		if !validIdentity(host) {
			return sourceResolution{}, errors.New("graylog source identity is missing or invalid")
		}
	}
	if err := checkSourceCaseOwnership(ctx, tx, resolved); err != nil {
		return sourceResolution{}, err
	}
	unique := map[string]bool{}
	result := []string{}
	for _, host := range resolved.hosts {
		// Match the source spelling used by configuration tracking: Graylog
		// pipelines can lowercase source while ADM keeps the device's case.
		// Both are exact quoted selectors for the same resolved identity; never
		// invent a short/FQDN alias or another node when a mapping exists.
		for _, spelling := range []string{host, strings.ToLower(host)} {
			if !unique[spelling] {
				result = append(result, spelling)
				unique[spelling] = true
			}
		}
	}
	sort.Strings(result)
	resolved.hosts = result
	return resolved, nil
}

func mappedSources(ctx context.Context, tx *sql.Tx, fqdn string) (sourceResolution, error) {
	if tx == nil {
		return sourceResolution{}, nil
	}
	// A terminal DNS root dot and letter case do not change a registered
	// firewall's identity. Keep mapped Graylog source values themselves intact.
	fqdn, valid := mappingIdentity(fqdn)
	if !valid {
		return sourceResolution{}, errors.New("graylog registered firewall identity is invalid")
	}
	queries := []struct {
		sql   string
		args  []any
		match string
	}{
		{`SELECT rowid, COALESCE(firewallname,''), COALESCE(cluster_hostnames,''), COALESCE(dns_name_full,'') FROM vpn_config WHERE lower(dns_name_full) IN (lower(?), lower(?)) LIMIT 2`, []any{fqdn, fqdn + "."}, "dns_name_full"},
		{`SELECT rowid, COALESCE(firewallname,''), COALESCE(cluster_hostnames,''), COALESCE(dns_name_full,'') FROM vpn_config WHERE lower(firewallname) IN (lower(?), lower(?)) OR lower(dns_name) IN (lower(?), lower(?)) LIMIT 2`, []any{fqdn, fqdn + ".", fqdn, fqdn + "."}, "exact_alias"},
	}
	if short := shortHostname(fqdn); short != fqdn {
		queries = append(queries, struct {
			sql   string
			args  []any
			match string
		}{`SELECT rowid, COALESCE(firewallname,''), COALESCE(cluster_hostnames,''), COALESCE(dns_name_full,'') FROM vpn_config WHERE lower(firewallname)=lower(?) OR lower(dns_name)=lower(?) OR lower(dns_name_full)=lower(?) LIMIT 2`, []any{short, short, short}, "short_alias"})
	}
	for _, query := range queries {
		rows, err := tx.QueryContext(ctx, query.sql, query.args...)
		if err != nil {
			return sourceResolution{}, errors.New("graylog source mapping lookup failed")
		}
		matches := 0
		var name, cluster, canonical string
		var rowID int64
		for rows.Next() {
			if err = rows.Scan(&rowID, &name, &cluster, &canonical); err != nil {
				break
			}
			matches++
		}
		readErr := rows.Err()
		_ = rows.Close()
		if err != nil || readErr != nil {
			return sourceResolution{}, errors.New("graylog source mapping lookup failed")
		}
		if matches > 1 {
			return sourceResolution{}, errors.New("graylog source mapping is ambiguous; collection was not widened")
		}
		if matches == 1 {
			if canonical != "" {
				canonical, valid = mappingIdentity(canonical)
				if !valid {
					return sourceResolution{}, errors.New("graylog source mapping contains an invalid canonical identity")
				}
			}
			// Aliases and unique short names cannot override a known conflicting
			// canonical FQDN. Legacy empty/short canonical values and explicitly
			// registered short names retain their existing matching behavior.
			if strings.Contains(fqdn, ".") && strings.Contains(canonical, ".") && !strings.EqualFold(canonical, fqdn) {
				return sourceResolution{}, errors.New("graylog source mapping conflicts with the registered firewall identity")
			}
			if len(cluster) > maxSourceIdentities*257 || len(name) > 256 {
				return sourceResolution{}, errors.New("graylog source mapping exceeds the supported identity size")
			}
			var hosts []string
			for _, host := range strings.Split(cluster, ",") {
				if host = strings.TrimSpace(host); host != "" {
					hosts = append(hosts, host)
				}
			}
			if len(hosts) > 0 {
				return sourceResolution{hosts: hosts, origin: "adm_vpn_cluster_hostnames", match: query.match, rowID: rowID}, nil
			}
			if cluster != "" {
				// The ADM status check treats a populated but unusable cluster
				// list as a mapping error; do not silently select firewallname.
				return sourceResolution{}, errors.New("graylog source mapping contains no usable cluster hostname")
			}
			if name != "" {
				return sourceResolution{hosts: []string{name}, origin: "adm_vpn_firewallname", match: query.match, rowID: rowID}, nil
			}
			return sourceResolution{}, errors.New("graylog source mapping contains no usable identity")
		}
	}
	return sourceResolution{}, nil
}

func (c *Collector) openSourceMapping() (*sql.DB, error) {
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
	db.SetMaxOpenConns(1)
	return db, nil
}

// Unlike a broad hostname retry, lowercase variants must not select another
// ADM entry. Configuration tracking applies the same case-folded ownership
// rule. Only a change in spelling requires this bounded scan; row content is
// streamed and never exported or used as additional query candidates.
func checkSourceCaseOwnership(ctx context.Context, tx *sql.Tx, resolved sourceResolution) error {
	if tx == nil {
		return nil
	}
	variants := map[string]bool{}
	for _, host := range resolved.hosts {
		if lower := strings.ToLower(host); lower != host {
			variants[lower] = true
		}
	}
	if len(variants) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT substr(COALESCE(firewallname,''),1,257), substr(COALESCE(cluster_hostnames,''),1,4113) FROM vpn_config WHERE rowid <> ? LIMIT 10001`, resolved.rowID)
	if err != nil {
		return errors.New("graylog source ownership could not be checked")
	}
	defer func() { _ = rows.Close() }()
	rowCount, byteCount := 0, 0
	for rows.Next() {
		var name, cluster string
		if err := rows.Scan(&name, &cluster); err != nil {
			return errors.New("graylog source ownership could not be checked")
		}
		rowCount++
		byteCount += len(name) + len(cluster)
		if rowCount > maxMappingRows || byteCount > maxMappingScanBytes || len(name) > 256 || len(cluster) > maxSourceIdentities*257 {
			return errors.New("graylog source ownership exceeds the supported mapping size")
		}
		hosts := []string{name}
		if cluster != "" {
			hosts = strings.Split(cluster, ",")
		}
		for _, host := range hosts {
			if variants[strings.ToLower(strings.TrimSpace(host))] {
				return errors.New("graylog source spelling is ambiguous across ADM VPN mappings; collection was not widened")
			}
		}
	}
	if rows.Err() != nil {
		return errors.New("graylog source ownership could not be checked")
	}
	return nil
}

// mappingIdentity accepts legacy unqualified names without imposing a new DNS
// character policy. Populated malformed values must not become absent or
// unqualified identities after normalization, so every label must be nonempty.
func mappingIdentity(value string) (string, bool) {
	if !validIdentity(value) {
		return "", false
	}
	value = strings.TrimSuffix(value, ".")
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return "", false
		}
	}
	return value, true
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
