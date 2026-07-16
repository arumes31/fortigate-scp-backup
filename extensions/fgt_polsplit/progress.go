package fgt_polsplit

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"
)

// progressState is the live status of one running analysis. The analyze
// request registers it under a client-generated id and advances it at each
// Graylog stage; the UI polls /progress?id=... while the request is in
// flight, so the operator sees which of the (up to ~10) sequential calls is
// currently running instead of a mute spinner.
type progressState struct {
	Step    int
	Total   int
	Message string
	Updated time.Time
}

// progressIDRe bounds accepted ids (the client sends a UUID); anything else
// degrades to no-op reporting rather than polluting the map.
var progressIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

// progressReporter registers a progress entry and returns the step function.
// An empty or invalid id yields a no-op, so callers never branch.
func (e *Extension) progressReporter(id string, total int) func(string) {
	if !progressIDRe.MatchString(id) {
		return func(string) {}
	}
	e.progressMu.Lock()
	e.progressByID[id] = &progressState{Total: total, Message: "Starting analysis", Updated: time.Now()}
	e.progressMu.Unlock()
	return func(msg string) {
		e.progressMu.Lock()
		defer e.progressMu.Unlock()
		p := e.progressByID[id]
		if p == nil {
			return
		}
		if p.Step < p.Total {
			p.Step++
		}
		p.Message = msg
		p.Updated = time.Now()
	}
}

// progressDone drops the entry once the analyze response has been written
// (deferred in the handler, so entries cannot leak).
func (e *Extension) progressDone(id string) {
	if !progressIDRe.MatchString(id) {
		return
	}
	e.progressMu.Lock()
	delete(e.progressByID, id)
	e.progressMu.Unlock()
}

// progressHandler reports the current stage of one analysis. Unknown ids
// (finished or never started) answer inactive so the poller just idles.
func (e *Extension) progressHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	e.progressMu.Lock()
	p, ok := e.progressByID[id]
	var out map[string]any
	if ok {
		out = map[string]any{"active": true, "step": p.Step, "total": p.Total, "message": p.Message}
	} else {
		out = map[string]any{"active": false}
	}
	e.progressMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
