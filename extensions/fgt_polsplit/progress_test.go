package fgt_polsplit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

// TestProgressLifecycle: register → step → poll → done → inactive; invalid
// ids degrade to no-ops without touching the store.
func TestProgressLifecycle(t *testing.T) {
	e := &Extension{progressByID: map[string]*progressState{}}
	const id = "11111111-2222-3333-4444-555555555555"

	report := e.progressReporter(id, 3, 1, 5)
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

	// A note publishes detail + sub-progress without consuming a step.
	e.progressNoter(id)("time step 3/24", 3, 24)
	got = poll(id)
	if got["step"] != float64(2) || got["detail"] != "time step 3/24" || got["sub"] != float64(3) || got["sub_total"] != float64(24) {
		t.Errorf("note result = %v", got)
	}

	// Steps never exceed the declared total; advancing clears the note.
	report("three")
	report("four")
	got = poll(id)
	if got["step"] != float64(3) {
		t.Errorf("step must cap at total: %v", got)
	}
	if got["detail"] != "" || got["sub"] != float64(0) {
		t.Errorf("step must clear the previous note: %v", got)
	}

	e.progressDone(id)
	if got := poll(id); got["active"] != false {
		t.Errorf("finished id must report inactive: %v", got)
	}

	// Invalid ids: reporter and noter are no-ops, nothing lands in the store.
	e.progressReporter("nope", 3, 1, 5)("x")
	e.progressReporter("", 3, 1, 5)("x")
	e.progressNoter("nope")("x", 1, 2)
	if len(e.progressByID) != 0 {
		t.Errorf("invalid ids leaked into the store: %v", e.progressByID)
	}
}

// TestProgressNoteContext: the note function survives the context round-trip
// and absent contexts degrade to a no-op.
func TestProgressNoteContext(t *testing.T) {
	var got string
	ctx := withProgressNote(context.Background(), func(d string, s, n int) {
		got = fmt.Sprintf("%s %d/%d", d, s, n)
	})
	progressNoteFrom(ctx)("chunk", 3, 24)
	if got != "chunk 3/24" {
		t.Errorf("note via context = %q", got)
	}
	progressNoteFrom(context.Background())("noop", 0, 0) // must not panic
}
