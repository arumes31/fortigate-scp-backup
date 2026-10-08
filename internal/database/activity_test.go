package database

import (
	"strings"
	"testing"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/models"
)

func TestActivityLogWhereUsesOnlyParameters(t *testing.T) {
	t.Parallel()
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(48 * time.Hour)
	filter := models.ActivityLogFilter{
		Query: "query-sentinel' OR TRUE", Username: "operator-sentinel",
		Action: "action-sentinel", From: from, To: to,
	}
	where, args := activityLogWhere(filter)
	for _, raw := range []string{filter.Query, filter.Username, filter.Action} {
		if strings.Contains(where, raw) {
			t.Fatalf("activity SQL contains raw filter %q: %s", raw, where)
		}
	}
	for _, placeholder := range []string{"$1", "$2", "$3", "$4", "$5"} {
		if !strings.Contains(where, placeholder) {
			t.Errorf("activity SQL missing %s: %s", placeholder, where)
		}
	}
	if len(args) != 5 || args[0] != filter.Query || args[1] != filter.Username || args[2] != filter.Action || args[3] != from || args[4] != to {
		t.Fatalf("activity SQL args = %#v", args)
	}
	if !strings.Contains(where, "timestamp >= $4") || !strings.Contains(where, "timestamp < $5") {
		t.Fatalf("activity SQL does not use inclusive/exclusive time bounds: %s", where)
	}
}

func TestActivityLogWhereAllowsEmptyFilter(t *testing.T) {
	t.Parallel()
	where, args := activityLogWhere(models.ActivityLogFilter{})
	if where != "" || len(args) != 0 {
		t.Fatalf("empty activity filter = %q / %#v", where, args)
	}
}
