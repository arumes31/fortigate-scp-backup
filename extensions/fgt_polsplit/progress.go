package fgt_polsplit

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"
)

// progressState is the live status of one running analysis. The analyze
// request registers it under a client-generated id and advances it at each
// Graylog stage; the UI polls /progress?id=... while the request is in
// flight, so the operator sees which of the (up to ~10) sequential calls is
// currently running instead of a mute spinner. Long stages additionally
// publish a detail line and sub-progress (x of n) — e.g. the chunked
// aggregation fallback stepping through sub-windows — without consuming a
// step.
type progressState struct {
	Step     int
	Total    int
	Message  string
	Detail   string // sub-stage note shown next to the message
	Sub      int    // sub-progress within the current step (0 = none)
	SubTotal int
	Updated  time.Time
}

// progressIDRe bounds accepted ids (the client sends a UUID); anything else
// degrades to no-op reporting rather than polluting the map.
var progressIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

// progressReporter registers a progress entry and returns the step function.
// An empty or invalid id yields a no-op, so callers never branch. Advancing a
// step clears the previous step's detail and sub-progress.
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
		p.Detail = ""
		p.Sub, p.SubTotal = 0, 0
		p.Updated = time.Now()
	}
}

// progressNoteFn publishes a sub-stage detail for the CURRENT step: a free
// text plus optional sub-progress counters (pass 0,0 for text-only notes).
// It never advances the step counter.
type progressNoteFn func(detail string, sub, subTotal int)

// progressNoter returns the note function for one analysis id (no-op for
// invalid ids, mirroring progressReporter).
func (e *Extension) progressNoter(id string) progressNoteFn {
	if !progressIDRe.MatchString(id) {
		return func(string, int, int) {}
	}
	return func(detail string, sub, subTotal int) {
		e.progressMu.Lock()
		defer e.progressMu.Unlock()
		p := e.progressByID[id]
		if p == nil {
			return
		}
		p.Detail = detail
		p.Sub, p.SubTotal = sub, subTotal
		p.Updated = time.Now()
	}
}

// progressNoteKey carries the note function through the request context, so
// deep Graylog helpers can publish sub-progress without threading an extra
// parameter through every call chain.
type progressNoteKey struct{}

func withProgressNote(ctx context.Context, fn progressNoteFn) context.Context {
	return context.WithValue(ctx, progressNoteKey{}, fn)
}

// progressNoteFrom returns the context's note function, or a no-op — callers
// never branch.
func progressNoteFrom(ctx context.Context) progressNoteFn {
	if fn, ok := ctx.Value(progressNoteKey{}).(progressNoteFn); ok && fn != nil {
		return fn
	}
	return func(string, int, int) {}
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
		out = map[string]any{
			"active": true, "step": p.Step, "total": p.Total, "message": p.Message,
			"detail": p.Detail, "sub": p.Sub, "sub_total": p.SubTotal,
		}
	} else {
		out = map[string]any{"active": false}
	}
	e.progressMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
