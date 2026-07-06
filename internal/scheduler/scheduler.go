// Package scheduler runs one recurring job per firewall. It replaces the
// Python APScheduler: jobs are rebuilt from the firewalls table at startup, so
// the apscheduler_jobs table is no longer needed. A ticker naturally drops
// ticks while a job is still running, giving the old coalesce / max_instances=1
// behavior (never more than one backup of the same firewall at a time).
package scheduler

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

type job struct {
	id       string
	interval time.Duration
	fn       func()
	cancel   context.CancelFunc
}

// Scheduler owns the set of recurring jobs.
type Scheduler struct {
	mu     sync.Mutex
	jobs   map[string]*job
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates an empty scheduler.
func New(logger *slog.Logger) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		jobs:   make(map[string]*job),
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Schedule registers a recurring job. The first run happens after firstDelay,
// then every interval. If a job with the same id already exists it is left
// untouched (matching "job already exists, skipping").
func (s *Scheduler) Schedule(id string, interval, firstDelay time.Duration, fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[id]; ok {
		s.logger.Warn("job already exists, skipping", "job", id)
		return
	}
	jctx, jcancel := context.WithCancel(s.ctx)
	j := &job{id: id, interval: interval, fn: fn, cancel: jcancel}
	s.jobs[id] = j
	s.wg.Add(1)
	go s.run(jctx, j, firstDelay)
	s.logger.Debug("scheduled job", "job", id, "interval", interval, "first_delay", firstDelay)
}

// Remove stops and forgets a job. No-op if the id is unknown.
func (s *Scheduler) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		j.cancel()
		delete(s.jobs, id)
		s.logger.Debug("removed job", "job", id)
	}
}

// Has reports whether a job id is currently scheduled.
func (s *Scheduler) Has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.jobs[id]
	return ok
}

// IDs returns the scheduled job ids, sorted.
func (s *Scheduler) IDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.jobs))
	for id := range s.jobs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Stop cancels every job and waits for in-flight runs to finish.
func (s *Scheduler) Stop() {
	s.cancel()
	s.wg.Wait()
}

func (s *Scheduler) run(ctx context.Context, j *job, firstDelay time.Duration) {
	defer s.wg.Done()

	select {
	case <-ctx.Done():
		return
	case <-time.After(firstDelay):
	}
	s.safeRun(j)

	t := time.NewTicker(j.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.safeRun(j)
		}
	}
}

func (s *Scheduler) safeRun(j *job) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("job panicked", "job", j.id, "recover", r)
		}
	}()
	j.fn()
}
