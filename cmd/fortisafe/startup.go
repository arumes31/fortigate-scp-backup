package main

import (
	"log/slog"
	"sync"
	"time"
)

const startupHeartbeatInterval = 15 * time.Second

// runStartupPhase makes blocking startup work observable without changing its
// ordering. The heartbeat stops before the final completion or failure event,
// so operators never see stale "still running" messages for a finished phase.
func runStartupPhase[T any](logger *slog.Logger, phase string, heartbeatInterval time.Duration, work func() (T, error)) (T, error) {
	if heartbeatInterval <= 0 {
		heartbeatInterval = startupHeartbeatInterval
	}

	started := time.Now()
	logger.Info("startup phase started", "phase", phase)

	done := make(chan struct{})
	var heartbeat sync.WaitGroup
	heartbeat.Add(1)
	go func() {
		defer heartbeat.Done()
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				logger.Info("startup phase still running",
					"phase", phase,
					"elapsed", now.Sub(started).Round(time.Second))
			case <-done:
				return
			}
		}
	}()

	value, err := work()
	close(done)
	heartbeat.Wait()
	duration := time.Since(started).Round(time.Millisecond)
	if err != nil {
		logger.Error("startup phase failed", "phase", phase, "duration", duration, "err", err)
		return value, err
	}
	logger.Info("startup phase completed", "phase", phase, "duration", duration)
	return value, nil
}

func runStartupAction(logger *slog.Logger, phase string, work func() error) error {
	_, err := runStartupPhase(logger, phase, startupHeartbeatInterval, func() (struct{}, error) {
		return struct{}{}, work()
	})
	return err
}
