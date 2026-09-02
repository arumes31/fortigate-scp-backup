package fgtconftail

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"
)

const (
	admVPNDatabaseName       = "fgt-adm-vpn-conf-db.db"
	maxCatalogAliasBytes     = 512
	maxSourceAliasesPerGroup = 25
	registeredFirewallsQuery = `SELECT id, COALESCE(fqdn, '') FROM firewalls ORDER BY id`
)

type sourceCoverage struct {
	FirewallID   int
	FirewallName string
	Aliases      []string
	Warnings     []string
}

type sourceCatalog struct {
	byAlias       map[string]firewallRef
	aliases       []string
	coverageRows  []sourceCoverage
	warningValues []string
}

type catalogFirewall struct {
	ref      firewallRef
	warnings map[string]struct{}
	enabled  bool
}

type aliasCandidate struct {
	owners   map[int]struct{}
	variants map[string]struct{}
}

type admAliasRow struct {
	firewallName     string
	dnsName          string
	dnsNameFull      string
	clusterHostnames string
	graylogEnabled   bool
}

type catalogBuilder struct {
	firewalls       []catalogFirewall
	aliasCandidates map[string]*aliasCandidate
	warnings        map[string]struct{}
	fullNames       map[string][]int
	shortNames      map[string][]int
}

func loadSourceCatalog(
	ctx context.Context,
	pool *pgxpool.Pool,
	dataDir string,
) (sourceCatalog, error) {
	if err := ctx.Err(); err != nil {
		return sourceCatalog{}, err
	}
	if pool == nil {
		return sourceCatalog{}, errors.New("fgt conftail source catalog: postgresql pool is nil")
	}

	rows, err := pool.Query(ctx, registeredFirewallsQuery)
	if err != nil {
		return sourceCatalog{}, fmt.Errorf("query registered firewalls: %w", err)
	}
	defer rows.Close()

	firewalls := make([]firewallRef, 0)
	for rows.Next() {
		var firewall firewallRef
		if err := rows.Scan(&firewall.ID, &firewall.Name); err != nil {
			return sourceCatalog{}, fmt.Errorf("scan registered firewall: %w", err)
		}
		firewalls = append(firewalls, firewall)
	}
	if err := rows.Err(); err != nil {
		return sourceCatalog{}, fmt.Errorf("iterate registered firewalls: %w", err)
	}

	return buildSourceCatalog(ctx, firewalls, dataDir)
}

func buildSourceCatalog(
	ctx context.Context,
	registered []firewallRef,
	dataDir string,
) (sourceCatalog, error) {
	if err := ctx.Err(); err != nil {
		return sourceCatalog{}, err
	}

	firewalls := append([]firewallRef{}, registered...)
	sort.SliceStable(firewalls, func(i, j int) bool {
		if firewalls[i].ID == firewalls[j].ID {
			return strings.ToLower(strings.TrimSpace(firewalls[i].Name)) <
				strings.ToLower(strings.TrimSpace(firewalls[j].Name))
		}
		return firewalls[i].ID < firewalls[j].ID
	})

	rows, isMissing, err := readADMAliasRows(ctx, dataDir)
	// Once the ADM VPN database exists, its per-firewall graylog_enabled flag
	// is authoritative. Before that optional database exists, retain the
	// registered-firewall fallback used during startup and standalone installs.
	builder := newCatalogBuilder(firewalls, !isMissing)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return sourceCatalog{}, contextErr
		}
		builder.addWarning(
			"ADM VPN alias database could not be read; using registered-firewall fallbacks: " + err.Error(),
		)
	} else if !isMissing {
		builder.addADMAliases(rows)
	}

	return builder.build(), nil
}

func newCatalogBuilder(registered []firewallRef, requireADMGraylogEnabled bool) *catalogBuilder {
	builder := &catalogBuilder{
		firewalls:       make([]catalogFirewall, 0, len(registered)),
		aliasCandidates: make(map[string]*aliasCandidate),
		warnings:        make(map[string]struct{}),
		fullNames:       make(map[string][]int),
		shortNames:      make(map[string][]int),
	}

	for _, registeredFirewall := range registered {
		registeredFirewall.Name = strings.TrimSpace(registeredFirewall.Name)
		registeredFirewall.Aliases = []string{}
		index := len(builder.firewalls)
		builder.firewalls = append(builder.firewalls, catalogFirewall{
			ref:      registeredFirewall,
			warnings: make(map[string]struct{}),
		})

		full, fullOK := normalizeSourceAlias(registeredFirewall.Name)
		if fullOK {
			builder.fullNames[full] = append(builder.fullNames[full], index)
		}

		shortName := shortFQDN(registeredFirewall.Name)
		short, shortOK := normalizeSourceAlias(shortName)
		if shortOK {
			builder.shortNames[short] = append(builder.shortNames[short], index)
		}
		if !requireADMGraylogEnabled {
			builder.enableFirewall(index)
		}
	}

	return builder
}

func (b *catalogBuilder) addADMAliases(rows []admAliasRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		left := admRowSortKey(rows[i])
		right := admRowSortKey(rows[j])
		return left < right
	})

	for _, row := range rows {
		if !row.graylogEnabled {
			continue
		}
		matches := b.matchRegisteredFirewalls(row)
		if len(matches) == 0 {
			continue
		}
		if len(matches) > 1 {
			label := firstValidAlias(row.dnsNameFull, row.firewallName, row.dnsName)
			warning := fmt.Sprintf(
				"ADM VPN row %q is ambiguous across registered firewalls; its aliases were excluded",
				label,
			)
			b.addWarning(warning)
			for _, index := range matches {
				b.addFirewallWarning(index, warning)
			}
			continue
		}

		index := matches[0]
		b.enableFirewall(index)
		usable := false
		if strings.TrimSpace(row.firewallName) != "" {
			usable = b.addAlias(index, row.firewallName, "ADM VPN firewallname") || usable
		}
		for _, hostname := range strings.Split(row.clusterHostnames, ",") {
			if strings.TrimSpace(hostname) == "" {
				continue
			}
			usable = b.addAlias(index, hostname, "ADM VPN cluster hostname") || usable
		}
		if !usable && strings.TrimSpace(row.firewallName) == "" &&
			strings.TrimSpace(row.clusterHostnames) == "" {
			b.addFirewallWarning(
				index,
				fmt.Sprintf(
					"ADM VPN mapping for registered firewall %d contains no source aliases",
					b.firewalls[index].ref.ID,
				),
			)
		}
	}
}

func (b *catalogBuilder) enableFirewall(index int) {
	if index < 0 || index >= len(b.firewalls) || b.firewalls[index].enabled {
		return
	}
	b.firewalls[index].enabled = true
	registered := b.firewalls[index].ref
	if _, ok := normalizeSourceAlias(registered.Name); ok {
		b.addAlias(index, registered.Name, "registered firewall name")
	} else {
		b.addFirewallWarning(
			index,
			fmt.Sprintf("registered firewall %d has an invalid FQDN source alias", registered.ID),
		)
	}
	shortName := shortFQDN(registered.Name)
	if _, ok := normalizeSourceAlias(shortName); ok {
		b.addAlias(index, shortName, "short-FQDN fallback")
	} else {
		b.addFirewallWarning(
			index,
			fmt.Sprintf("registered firewall %d has no valid short-FQDN source alias", registered.ID),
		)
	}
}

func (b *catalogBuilder) matchRegisteredFirewalls(row admAliasRow) []int {
	identities := []string{row.dnsNameFull, row.firewallName, row.dnsName}
	if matches := matchingFirewallIndexes(identities, b.fullNames); len(matches) > 0 {
		return matches
	}
	return matchingFirewallIndexes(identities, b.shortNames)
}

func matchingFirewallIndexes(values []string, index map[string][]int) []int {
	matches := make(map[int]struct{})
	for _, value := range values {
		key, ok := normalizeSourceAlias(value)
		if !ok {
			continue
		}
		for _, firewallIndex := range index[key] {
			matches[firewallIndex] = struct{}{}
		}
	}

	result := make([]int, 0, len(matches))
	for firewallIndex := range matches {
		result = append(result, firewallIndex)
	}
	sort.Ints(result)
	return result
}

func (b *catalogBuilder) addAlias(index int, rawAlias, origin string) bool {
	rawAlias = strings.TrimSpace(rawAlias)
	alias, ok := normalizeSourceAlias(rawAlias)
	if !ok {
		b.addFirewallWarning(
			index,
			fmt.Sprintf(
				"registered firewall %d has an invalid %s",
				b.firewalls[index].ref.ID,
				origin,
			),
		)
		return false
	}

	candidate, exists := b.aliasCandidates[alias]
	if !exists {
		candidate = &aliasCandidate{
			owners:   make(map[int]struct{}),
			variants: make(map[string]struct{}),
		}
		b.aliasCandidates[alias] = candidate
	}
	candidate.owners[index] = struct{}{}
	candidate.variants[rawAlias] = struct{}{}
	// Graylog source matching is case-sensitive. Keep every exact observed
	// spelling and also query the normalized lowercase spelling commonly emitted
	// by syslog pipelines; local resolution already uses the same normalized key.
	candidate.variants[alias] = struct{}{}
	return true
}

func (b *catalogBuilder) addFirewallWarning(index int, warning string) {
	b.firewalls[index].warnings[warning] = struct{}{}
	b.addWarning(warning)
}

func (b *catalogBuilder) addWarning(warning string) {
	warning = strings.TrimSpace(warning)
	if warning != "" {
		b.warnings[warning] = struct{}{}
	}
}

func (b *catalogBuilder) build() sourceCatalog {
	aliases := make([]string, 0, len(b.aliasCandidates))
	for alias := range b.aliasCandidates {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	acceptedOwners := make(map[string]int, len(aliases))
	acceptedByFirewall := make([][]string, len(b.firewalls))
	for i := range acceptedByFirewall {
		acceptedByFirewall[i] = []string{}
	}
	for _, alias := range aliases {
		candidate := b.aliasCandidates[alias]
		owners := make([]int, 0, len(candidate.owners))
		for index := range candidate.owners {
			owners = append(owners, index)
		}
		sort.Ints(owners)
		if len(owners) != 1 {
			warning := fmt.Sprintf(
				"source alias %q is ambiguous across registered firewalls and was excluded",
				alias,
			)
			b.addWarning(warning)
			for _, index := range owners {
				b.firewalls[index].warnings[warning] = struct{}{}
			}
			continue
		}
		acceptedOwners[alias] = owners[0]
		variants := sortedAliasVariants(candidate.variants)
		acceptedByFirewall[owners[0]] = append(acceptedByFirewall[owners[0]], variants...)
	}

	coverageRows := make([]sourceCoverage, 0, len(b.firewalls))
	for index := range b.firewalls {
		if !b.firewalls[index].enabled {
			continue
		}
		aliasesForFirewall := acceptedByFirewall[index]
		if len(aliasesForFirewall) == 0 {
			warning := fmt.Sprintf(
				"registered firewall %d has no unambiguous Graylog source alias",
				b.firewalls[index].ref.ID,
			)
			b.firewalls[index].warnings[warning] = struct{}{}
			b.addWarning(warning)
		}
		b.firewalls[index].ref.Aliases = append([]string{}, aliasesForFirewall...)
		coverageRows = append(coverageRows, sourceCoverage{
			FirewallID:   b.firewalls[index].ref.ID,
			FirewallName: b.firewalls[index].ref.Name,
			Aliases:      append([]string{}, aliasesForFirewall...),
			Warnings:     sortedSetValues(b.firewalls[index].warnings),
		})
	}

	acceptedAliases := make([]string, 0, len(acceptedOwners))
	byAlias := make(map[string]firewallRef, len(acceptedOwners))
	for _, alias := range aliases {
		index, accepted := acceptedOwners[alias]
		if !accepted {
			continue
		}
		acceptedAliases = append(
			acceptedAliases,
			sortedAliasVariants(b.aliasCandidates[alias].variants)...,
		)
		byAlias[alias] = cloneFirewallRef(b.firewalls[index].ref)
	}

	return sourceCatalog{
		byAlias:       byAlias,
		aliases:       acceptedAliases,
		coverageRows:  coverageRows,
		warningValues: sortedSetValues(b.warnings),
	}
}

func (c sourceCatalog) resolve(source string) (firewallRef, bool) {
	alias, ok := normalizeSourceAlias(source)
	if !ok {
		return firewallRef{}, false
	}
	firewall, ok := c.byAlias[alias]
	if !ok {
		return firewallRef{}, false
	}
	return cloneFirewallRef(firewall), true
}

func (c sourceCatalog) sourceGroups() [][]string {
	groupCount := (len(c.aliases) + maxSourceAliasesPerGroup - 1) / maxSourceAliasesPerGroup
	groups := make([][]string, 0, groupCount)
	for start := 0; start < len(c.aliases); start += maxSourceAliasesPerGroup {
		end := min(start+maxSourceAliasesPerGroup, len(c.aliases))
		groups = append(groups, append([]string{}, c.aliases[start:end]...))
	}
	return groups
}

func (c sourceCatalog) coverage() []sourceCoverage {
	result := make([]sourceCoverage, 0, len(c.coverageRows))
	for _, row := range c.coverageRows {
		row.Aliases = append([]string{}, row.Aliases...)
		row.Warnings = append([]string{}, row.Warnings...)
		result = append(result, row)
	}
	return result
}

func (c sourceCatalog) warnings() []string {
	return append([]string{}, c.warningValues...)
}

func readADMAliasRows(
	ctx context.Context,
	dataDir string,
) (result []admAliasRow, isMissing bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(dataDir) == "" {
		return nil, false, errors.New("data directory is empty")
	}

	databasePath := filepath.Join(dataDir, admVPNDatabaseName)
	info, err := os.Stat(databasePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []admAliasRow{}, true, nil
		}
		return nil, false, fmt.Errorf("stat adm vpn alias database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("adm vpn alias database is not a regular file")
	}

	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(databasePath))
	if err != nil {
		return nil, false, fmt.Errorf("open adm vpn alias database: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close adm vpn alias database: %w", closeErr))
		}
	}()

	rows, err := db.QueryContext(ctx, `SELECT COALESCE(firewallname, ''),
		COALESCE(dns_name, ''), COALESCE(dns_name_full, ''),
		COALESCE(cluster_hostnames, ''), COALESCE(graylog_enabled, 0)
		FROM vpn_config`)
	if err != nil {
		return nil, false, fmt.Errorf("query adm vpn aliases: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close adm vpn alias rows: %w", closeErr))
		}
	}()

	result = make([]admAliasRow, 0)
	for rows.Next() {
		var row admAliasRow
		if err := rows.Scan(
			&row.firewallName,
			&row.dnsName,
			&row.dnsNameFull,
			&row.clusterHostnames,
			&row.graylogEnabled,
		); err != nil {
			return nil, false, fmt.Errorf("scan adm vpn alias row: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate adm vpn alias rows: %w", err)
	}
	return result, false, nil
}

func sqliteReadOnlyDSN(databasePath string) string {
	path := filepath.ToSlash(databasePath)
	if filepath.VolumeName(databasePath) != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	location := url.URL{Scheme: "file", Path: path}
	query := location.Query()
	query.Set("mode", "ro")
	location.RawQuery = query.Encode()
	return location.String()
}

func normalizeSourceAlias(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxCatalogAliasBytes ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") ||
		strings.Contains(value, "..") {
		return "", false
	}

	hasLetterOrDigit := false
	for _, character := range value {
		isSeparator := character == '-' || character == '_' || character == '.'
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) && !isSeparator {
			return "", false
		}
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			hasLetterOrDigit = true
		}
	}
	if !hasLetterOrDigit {
		return "", false
	}
	return strings.ToLower(value), true
}

func shortFQDN(value string) string {
	value = strings.TrimSpace(value)
	if separator := strings.IndexByte(value, '.'); separator >= 0 {
		return value[:separator]
	}
	return value
}

func admRowSortKey(row admAliasRow) string {
	return strings.ToLower(strings.Join([]string{
		strings.TrimSpace(row.dnsNameFull),
		strings.TrimSpace(row.dnsName),
		strings.TrimSpace(row.firewallName),
		strings.TrimSpace(row.clusterHostnames),
	}, "\x00"))
}

func firstValidAlias(values ...string) string {
	for _, value := range values {
		if alias, ok := normalizeSourceAlias(value); ok {
			return alias
		}
	}
	return "invalid mapping"
}

func cloneFirewallRef(firewall firewallRef) firewallRef {
	firewall.Aliases = append([]string{}, firewall.Aliases...)
	return firewall
}

func sortedSetValues(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedAliasVariants(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		left := strings.ToLower(result[i])
		right := strings.ToLower(result[j])
		if left == right {
			return result[i] < result[j]
		}
		return left < right
	})
	return result
}
