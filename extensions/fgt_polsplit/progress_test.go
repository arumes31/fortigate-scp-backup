package fgt_polsplit

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestProgressLifecycle: register → step → poll → done → inactive; invalid
// ids degrade to no-ops without touching the store.
func TestProgressLifecycle(t *testing.T) {
	e := &Extension{progressByID: map[string]*progressState{}}
	const id = "11111111-2222-3333-4444-555555555555"

	report := e.progressReporter(id, 3)
	report("step one")
	report("step two")

	poll := func(qid string) map[string]any {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/fgt-polsplit/progress?id="+qid, nil)
		e.progressHandler(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	got := poll(id)
	if got["active"] != true || got["step"] != float64(2) || got["total"] != float64(3) || got["message"] != "step two" {
		t.Errorf("progress = %v", got)
	}

	// Steps never exceed the declared total.
	report("three")
	report("four")
	if got := poll(id); got["step"] != float64(3) {
		t.Errorf("step must cap at total: %v", got)
	}

	e.progressDone(id)
	if got := poll(id); got["active"] != false {
		t.Errorf("finished id must report inactive: %v", got)
	}

	// Invalid ids: reporter is a no-op and nothing lands in the store.
	e.progressReporter("nope", 3)("x")
	e.progressReporter("", 3)("x")
	if len(e.progressByID) != 0 {
		t.Errorf("invalid ids leaked into the store: %v", e.progressByID)
	}
}
