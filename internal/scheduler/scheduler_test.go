package scheduler

import (
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func testScheduler() *Scheduler { return New(slog.New(slog.DiscardHandler)) }

func TestScheduleAndRemove(t *testing.T) {
	s := testScheduler()
	defer s.Stop()

	var runs int32
	s.Schedule("job1", time.Hour, 20*time.Millisecond, func() { atomic.AddInt32(&runs, 1) })
	if !s.Has("job1") {
		t.Fatal("job should exist")
	}
	time.Sleep(60 * time.Millisecond)
	if atomic.LoadInt32(&runs) == 0 {
		t.Fatal("job should have fired after the first delay")
	}
	s.Remove("job1")
	if s.Has("job1") {
		t.Fatal("job should be removed")
	}
}

func TestScheduleDuplicateIgnored(t *testing.T) {
	s := testScheduler()
	defer s.Stop()
	s.Schedule("dup", time.Hour, time.Hour, func() {})
	s.Schedule("dup", time.Hour, time.Hour, func() {})
	if got := len(s.IDs()); got != 1 {
		t.Fatalf("expected 1 job, got %d", got)
	}
}

func TestScheduleCronInvalid(t *testing.T) {
	s := testScheduler()
	defer s.Stop()
	if err := s.ScheduleCron("bad", "not a cron", func() {}); err == nil {
		t.Fatal("expected error for invalid cron")
	}
}

func TestScheduleCronNextRun(t *testing.T) {
	s := testScheduler()
	defer s.Stop()
	if err := s.ScheduleCron("nightly", "0 3 * * *", func() {}); err != nil {
		t.Fatal(err)
	}
	info, ok := s.Info("nightly")
	if !ok {
		t.Fatal("expected job info")
	}
	if info.NextRun.IsZero() || !info.NextRun.After(time.Now()) {
		t.Fatalf("next run should be in the future, got %v", info.NextRun)
	}
	if info.Cron != "0 3 * * *" {
		t.Fatalf("cron mismatch: %q", info.Cron)
	}
}
