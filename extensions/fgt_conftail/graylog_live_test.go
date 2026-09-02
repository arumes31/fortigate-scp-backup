//go:build integration

package fgtconftail

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const liveConfTailQuery = `type:event AND subtype:system AND (` +
	`logid:0100044544 OR logid:0100044545 OR logid:0100044546 OR logid:0100044547)`

func TestGraylogLiveConfTailQueries(t *testing.T) {
	graylogURL := strings.TrimSpace(os.Getenv("GRAYLOG_URL"))
	graylogToken := strings.TrimSpace(os.Getenv("GRAYLOG_TOKEN"))
	if graylogURL == "" || graylogToken == "" {
		t.Skip("set GRAYLOG_URL and GRAYLOG_TOKEN to run the live Graylog integration test")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	client, err := newGraylogClient(graylogURL, graylogToken, nil)
	if err != nil {
		t.Fatalf("create Graylog client: %v", err)
	}

	dataDir := strings.TrimSpace(os.Getenv("FGT_CONFTAIL_TEST_DATA_DIR"))
	if dataDir == "" {
		dataDir = filepath.Join("..", "..", "data")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		t.Fatalf("resolve ADM data directory: %v", err)
	}
	aliasRows, missing, err := readADMAliasRows(ctx, dataDir)
	if err != nil {
		t.Fatalf("read ADM aliases: %v", err)
	}

	registered := make([]firewallRef, 0, len(aliasRows))
	seen := make(map[string]struct{}, len(aliasRows))
	for _, row := range aliasRows {
		name := strings.TrimSpace(row.firewallName)
		key := strings.ToLower(name)
		if name == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		registered = append(registered, firewallRef{
			ID:   len(registered) + 1,
			Name: name,
		})
	}

	groups := [][]string{}
	if !missing {
		catalog, err := buildSourceCatalog(ctx, registered, dataDir)
		if err != nil {
			t.Fatalf("build ConfTail source catalog: %v", err)
		}
		groups = catalog.sourceGroups()
	}

	to := time.Now().UTC()
	from := to.Add(-24 * time.Hour)
	fetchPage := func(groupIndex int, sources []string) []RawEvent {
		t.Helper()
		query, err := composeGraylogQuery(liveConfTailQuery, sources)
		if err != nil {
			t.Fatalf("compose source group %d query: %v", groupIndex, err)
		}
		events, err := client.fetchPage(ctx, graylogSearchRequest{
			Query:  query,
			Fields: graylogSelectedFields,
			From:   0,
			Size:   graylogDefaultPageSize,
			Timerange: graylogAbsoluteTimerange{
				Type: "absolute",
				From: from.Format(time.RFC3339Nano),
				To:   to.Format(time.RFC3339Nano),
			},
			Sort:      "gl2_message_id",
			SortOrder: "asc",
		})
		if err != nil {
			t.Fatalf("fetch source group %d: %v", groupIndex, err)
		}
		return events
	}

	baseEvents := fetchPage(0, nil)
	if len(baseEvents) == 0 {
		t.Fatal("ConfTail base query returned no configuration events in the last 24 hours")
	}
	if len(groups) == 0 {
		discoveredSet := make(map[string]struct{})
		for _, event := range baseEvents {
			source := strings.TrimSpace(event.Source)
			if source != "" {
				discoveredSet[source] = struct{}{}
			}
		}
		discovered := make([]string, 0, len(discoveredSet))
		for source := range discoveredSet {
			discovered = append(discovered, source)
		}
		sort.Strings(discovered)
		for start := 0; start < len(discovered); start += maxSourceAliasesPerGroup {
			end := min(start+maxSourceAliasesPerGroup, len(discovered))
			groups = append(groups, append([]string{}, discovered[start:end]...))
		}
	}
	if len(groups) == 0 {
		t.Fatal("ConfTail base query rows contain no source aliases")
	}

	totalAliases := 0
	totalRows := 0
	missingEventTimes := 0
	for _, event := range baseEvents {
		if event.EventTime.String() == "" {
			missingEventTimes++
		}
	}
	for groupIndex, sources := range groups {
		events := fetchPage(groupIndex+1, sources)
		allowedSources := make(map[string]struct{}, len(sources))
		for _, source := range sources {
			allowedSources[source] = struct{}{}
		}

		totalAliases += len(sources)
		totalRows += len(events)
		for _, event := range events {
			if _, allowed := allowedSources[event.Source]; !allowed {
				t.Fatalf("source group %d returned a row outside its requested aliases", groupIndex+1)
			}
			if event.EventTime.String() == "" {
				missingEventTimes++
			}
		}
	}

	t.Logf(
		"ConfTail live query succeeded: base_rows=%d groups=%d aliases=%d grouped_rows=%d missing_eventtime_rows=%d",
		len(baseEvents),
		len(groups),
		totalAliases,
		totalRows,
		missingEventTimes,
	)
	if totalRows == 0 {
		t.Fatal("ConfTail live query returned no configuration events in the last 24 hours")
	}
}
