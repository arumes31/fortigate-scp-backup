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

// runningEntry is one in-flight operation tracked for the dashboard.
type runningEntry struct {
	kind    string // "devicedata" | "sshdiag"
	fwID    int
	started time.Time
}

// trackRunning registers an in-flight operation and returns the function that
// removes it again (deferred by the caller). Entries are keyed by a sequence
// number, so concurrent operations of the same kind on the same firewall
// (e.g. a manual refresh racing the background sweep) never clobber each other.
func (e *Extension) trackRunning(kind string, fwID int) func() {
	e.runningMu.Lock()
	e.runningSeq++
	id := e.runningSeq
	if e.running == nil {
		e.running = map[int]runningEntry{}
	}
	e.running[id] = runningEntry{kind: kind, fwID: fwID, started: time.Now()}
	e.runningMu.Unlock()
	return func() {
		e.runningMu.Lock()
		delete(e.running, id)
		e.runningMu.Unlock()
	}
}

// RunningFetch is one in-flight operation, projected for the core dashboard's
// "currently running" card: a Graylog device-data refresh or a live SSH
// diagnostics collection.
type RunningFetch struct {
	Kind    string // "devicedata" | "sshdiag"
	FwID    int
	Started time.Time
}

// RunningFetches returns the currently running device-data refreshes and SSH
// diagnostics runs (empty when the extension is disabled or idle), newest
// first.
func RunningFetches() []RunningFetch {
	e := liveExt.Load()
	if e == nil {
		return nil
	}
	e.runningMu.Lock()
	defer e.runningMu.Unlock()
	out := make([]RunningFetch, 0, len(e.running))
	for _, r := range e.running {
		out = append(out, RunningFetch{Kind: r.kind, FwID: r.fwID, Started: r.started})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out
}
