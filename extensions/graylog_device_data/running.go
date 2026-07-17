package graylogdevicedata

import (
	"sort"
	"sync/atomic"
	"time"
)

// liveExt is the mounted extension instance, published so the core dashboard
// can list in-flight fetches without holding a reference to the extension
// (the same pattern as fgt_polsplit's RunningAnalyses).
var liveExt atomic.Pointer[Extension]

// runningEntry is one in-flight operation tracked for the dashboard, with an
// optional live sub-stage (detail + step counters) published via the note
// function trackRunning returns.
type runningEntry struct {
	kind    string // "devicedata" | "sshdiag"
	fwID    int
	started time.Time
	detail  string
	step    int
	total   int
}

// broadcast publishes an operation lifecycle event to the core SSE stream
// (no-op when the host did not wire the hook).
func (e *Extension) broadcast(kind string, fwID int, status string) {
	if e.broadcastOp != nil {
		e.broadcastOp(kind, fwID, status)
	}
}

// trackRunning registers an in-flight operation and returns a note function
// (publishing the current sub-stage for the dashboard, pass 0,0 for text-only
// notes) plus the removal function (deferred by the caller). Entries are
// keyed by a sequence number, so concurrent operations of the same kind on
// the same firewall (e.g. a manual refresh racing the background sweep)
// never clobber each other. Start and finish are also broadcast on the core
// SSE stream for SYS_STDOUT.
func (e *Extension) trackRunning(kind string, fwID int) (note func(detail string, step, total int), done func()) {
	e.runningMu.Lock()
	e.runningSeq++
	id := e.runningSeq
	if e.running == nil {
		e.running = map[int]*runningEntry{}
	}
	ent := &runningEntry{kind: kind, fwID: fwID, started: time.Now()}
	e.running[id] = ent
	e.runningMu.Unlock()
	e.broadcast(kind, fwID, "started")
	note = func(detail string, step, total int) {
		e.runningMu.Lock()
		ent.detail, ent.step, ent.total = detail, step, total
		e.runningMu.Unlock()
	}
	done = func() {
		e.runningMu.Lock()
		delete(e.running, id)
		e.runningMu.Unlock()
		e.broadcast(kind, fwID, "finished")
	}
	return note, done
}

// liveWindow is how long after the last live topology poll a firewall still
// counts as being watched live. The topology page polls every ~60s while its
// "Live" mode is on, so a missed beat keeps the row and a stopped/expired
// live mode drops it within two minutes.
const liveWindow = 2 * time.Minute

// liveState tracks one firewall's live-mode polling for the dashboard row:
// when the current live session began and when it last polled.
type liveState struct {
	started, last time.Time
}

// markLive records a live topology poll (the ?range= short-window refresh)
// so the dashboard can show a persistent "live view" row between polls. A new
// live session (no recent poll) is broadcast as started.
func (e *Extension) markLive(fwID int) {
	now := time.Now()
	e.runningMu.Lock()
	if e.liveByFw == nil {
		e.liveByFw = map[int]*liveState{}
	}
	fresh := false
	if st := e.liveByFw[fwID]; st != nil && now.Sub(st.last) <= liveWindow {
		st.last = now
	} else {
		e.liveByFw[fwID] = &liveState{started: now, last: now}
		fresh = true
	}
	e.runningMu.Unlock()
	if fresh {
		e.broadcast("live", fwID, "started")
	}
}

// RunningFetch is one in-flight operation, projected for the core dashboard's
// "currently running" card: a Graylog device-data refresh, a live SSH
// diagnostics collection, or an active topology live view.
type RunningFetch struct {
	Kind    string // "devicedata" | "sshdiag" | "live"
	FwID    int
	Started time.Time
	Detail  string // current sub-stage ("STP / guard states", "switch 2/5: SW1")
	Step    int    // 0 when the stage has no counter
	Total   int
}

// RunningFetches returns the currently running device-data refreshes, SSH
// diagnostics runs and active live views (empty when the extension is
// disabled or idle), newest first.
func RunningFetches() []RunningFetch {
	e := liveExt.Load()
	if e == nil {
		return nil
	}
	e.runningMu.Lock()
	out := make([]RunningFetch, 0, len(e.running)+len(e.liveByFw))
	for _, r := range e.running {
		out = append(out, RunningFetch{Kind: r.kind, FwID: r.fwID, Started: r.started,
			Detail: r.detail, Step: r.step, Total: r.total})
	}
	now := time.Now()
	var liveEnded []int
	for fwID, st := range e.liveByFw {
		if now.Sub(st.last) > liveWindow {
			delete(e.liveByFw, fwID) // live mode stopped or expired
			liveEnded = append(liveEnded, fwID)
			continue
		}
		out = append(out, RunningFetch{Kind: "live", FwID: fwID, Started: st.started})
	}
	e.runningMu.Unlock()
	for _, fwID := range liveEnded {
		e.broadcast("live", fwID, "finished")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out
}
