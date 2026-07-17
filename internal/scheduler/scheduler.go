// Package scheduler runs one recurring job per firewall. It replaces the Python
// APScheduler: jobs are rebuilt from the firewalls table at startup. A job runs
// either on a fixed interval or on a cron expression. Runs never overlap for the
// same job (the run loop is sequential), giving the old coalesce /
// max_instances=1 behavior.
package scheduler

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

// JobInfo is a read-only snapshot of a job's timing, for the UI.
type JobInfo struct {
	ID      string
	LastRun time.Time
	NextRun time.Time
	Cron    string
	// Interval is the job's cadence: the configured interval for interval
	// jobs, or the gap between the next two activations for cron jobs (0 when
	// it cannot be determined). Callers use it to judge backup staleness.
	Interval time.Duration
}

type job struct {
	id       string
	interval time.Duration
	schedule cron.Schedule // non-nil for cron jobs
	cronExpr string
	fn       func()
	cancel   context.CancelFunc

	mu      sync.Mutex
	lastRun time.Time
	nextRun time.Time
}

func (j *job) setNext(t time.Time) {
	j.mu.Lock()
	j.nextRun = t
	j.mu.Unlock()
}

func (j *job) markRun(now time.Time) {
	j.mu.Lock()
	j.lastRun = now
	j.mu.Unlock()
}

func (j *job) info() JobInfo {
	j.mu.Lock()
	defer j.mu.Unlock()
	interval := j.interval
	if j.schedule != nil {
		// Cron cadence: the gap between the next two activations from now.
		n1 := j.schedule.Next(time.Now())
		if n2 := j.schedule.Next(n1); !n2.IsZero() && !n1.IsZero() {
			interval = n2.Sub(n1)
		}
	}
	return JobInfo{ID: j.id, LastRun: j.lastRun, NextRun: j.nextRun, Cron: j.cronExpr, Interval: interval}
}

// Scheduler owns the set of recurring jobs.
type Scheduler struct {
	mu     sync.Mutex
	jobs   map[string]*job
	logger *slog.Logger
	parser cron.Parser
	tz     *time.Location
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates an empty scheduler. tz is the wall clock cron expressions are
// evaluated against; a nil tz falls back to the process local time.
func New(logger *slog.Logger, tz *time.Location) *Scheduler {
	if tz == nil {
		tz = time.Local
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		jobs:   make(map[string]*job),
		logger: logger,
		parser: cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow),
		tz:     tz,
		ctx:    ctx,
		cancel: cancel,
	}
}

// now returns the current time in the scheduler's configured timezone, so cron
// expressions fire on the intended wall clock regardless of the host's TZ.
func (s *Scheduler) now() time.Time { return time.Now().In(s.tz) }

// Schedule registers an interval job (first run after firstDelay, then every
// interval). Existing ids are left untouched.
func (s *Scheduler) Schedule(id string, interval, firstDelay time.Duration, fn func()) {
	if interval <= 0 {
		// time.NewTicker in runInterval panics on a non-positive interval, and that
		// panic is outside the per-fire recover, so reject it up front.
		s.logger.Warn("invalid interval, not scheduling job", "job", id, "interval", interval)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[id]; ok {
		s.logger.Warn("job already exists, skipping", "job", id)
		return
	}
	jctx, jcancel := context.WithCancel(s.ctx)
	j := &job{id: id, interval: interval, fn: fn, cancel: jcancel}
	j.setNext(time.Now().Add(firstDelay))
	s.jobs[id] = j
	s.wg.Add(1)
	go s.runInterval(jctx, j, firstDelay)
	s.logger.Debug("scheduled interval job", "job", id, "interval", interval, "first_delay", firstDelay)
}

// ScheduleCron registers a cron job. Returns an error if the expression is
// invalid (the caller may fall back to an interval).
func (s *Scheduler) ScheduleCron(id, spec string, fn func()) error {
	sched, err := s.parser.Parse(spec)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[id]; ok {
		s.logger.Warn("job already exists, skipping", "job", id)
		return nil
	}
	jctx, jcancel := context.WithCancel(s.ctx)
	j := &job{id: id, schedule: sched, cronExpr: spec, fn: fn, cancel: jcancel}
	j.setNext(sched.Next(s.now()))
	s.jobs[id] = j
	s.wg.Add(1)
	go s.runCron(jctx, j)
	s.logger.Debug("scheduled cron job", "job", id, "cron", spec)
	return nil
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

// Info returns the timing snapshot for a job.
func (s *Scheduler) Info(id string) (JobInfo, bool) {
	s.mu.Lock()
	j, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		return JobInfo{}, false
	}
	return j.info(), true
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

func (s *Scheduler) runInterval(ctx context.Context, j *job, firstDelay time.Duration) {
	defer s.wg.Done()
	select {
	case <-ctx.Done():
		return
	case <-time.After(firstDelay):
	}
	s.fire(j)
	j.setNext(time.Now().Add(j.interval))

	t := time.NewTicker(j.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.fire(j)
			j.setNext(time.Now().Add(j.interval))
		}
	}
}

func (s *Scheduler) runCron(ctx context.Context, j *job) {
	defer s.wg.Done()
	for {
		next := j.schedule.Next(s.now())
		j.setNext(next)
		wait := time.Until(next)
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			s.fire(j)
		}
	}
}

func (s *Scheduler) fire(j *job) {
	j.markRun(time.Now())
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("job panicked", "job", j.id, "recover", r)
		}
	}()
	j.fn()
}
