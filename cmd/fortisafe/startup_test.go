package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestRunStartupPhaseReportsProgressAndCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))

		got, err := runStartupPhase(logger, "database_schema", 10*time.Second, func() (string, error) {
			time.Sleep(25 * time.Second)
			return "ready", nil
		})
		if err != nil {
			t.Fatalf("runStartupPhase() error = %v", err)
		}
		if got != "ready" {
			t.Fatalf("runStartupPhase() value = %q, want ready", got)
		}

		events := startupLogEvents(t, output.String())
		wantMessages := []string{
			"startup phase started",
			"startup phase still running",
			"startup phase still running",
			"startup phase completed",
		}
		if len(events) != len(wantMessages) {
			t.Fatalf("startup events = %v, want messages %v", events, wantMessages)
		}
		for i, want := range wantMessages {
			if events[i].Message != want {
				t.Errorf("event %d message = %q, want %q", i, events[i].Message, want)
			}
			if events[i].Phase != "database_schema" {
				t.Errorf("event %d phase = %q, want database_schema", i, events[i].Phase)
			}
		}
		if events[1].Elapsed == 0 || events[2].Elapsed <= events[1].Elapsed {
			t.Errorf("heartbeat elapsed values = %v, want increasing positive durations", []time.Duration{events[1].Elapsed, events[2].Elapsed})
		}
		if events[3].Duration != 25*time.Second {
			t.Errorf("completion duration = %v, want 25s", events[3].Duration)
		}
	})
}

func TestRunStartupPhaseReportsFailure(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	wantErr := errors.New("migration locked")

	_, err := runStartupPhase(logger, "database_migrations", time.Hour, func() (struct{}, error) {
		return struct{}{}, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("runStartupPhase() error = %v, want %v", err, wantErr)
	}

	events := startupLogEvents(t, output.String())
	if len(events) != 2 {
		t.Fatalf("startup events = %v, want start and failure", events)
	}
	if events[0].Message != "startup phase started" || events[1].Message != "startup phase failed" {
		t.Fatalf("startup messages = %q, %q", events[0].Message, events[1].Message)
	}
	if !strings.Contains(events[1].Error, wantErr.Error()) {
		t.Errorf("failure error = %q, want it to contain %q", events[1].Error, wantErr)
	}
}

type startupLogEvent struct {
	Message  string        `json:"msg"`
	Phase    string        `json:"phase"`
	Elapsed  time.Duration `json:"elapsed"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"err"`
}

func startupLogEvents(t *testing.T, output string) []startupLogEvent {
	t.Helper()
	var events []startupLogEvent
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		var event startupLogEvent
		if err := event.UnmarshalJSON(scanner.Bytes()); err != nil {
			t.Fatalf("decode startup log %q: %v", scanner.Text(), err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan startup logs: %v", err)
	}
	return events
}

func (e *startupLogEvent) UnmarshalJSON(data []byte) error {
	type wireEvent struct {
		Message  string `json:"msg"`
		Phase    string `json:"phase"`
		Elapsed  int64  `json:"elapsed"`
		Duration int64  `json:"duration"`
		Error    string `json:"err"`
	}
	var wire wireEvent
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	e.Message = wire.Message
	e.Phase = wire.Phase
	e.Elapsed = time.Duration(wire.Elapsed)
	e.Duration = time.Duration(wire.Duration)
	e.Error = wire.Error
	return nil
}
