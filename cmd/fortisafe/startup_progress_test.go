package main

import (
	"testing"
	"time"
)

func TestStartupHeartbeatIntervalIsOperatorFriendly(t *testing.T) {
	t.Parallel()

	if startupHeartbeatInterval != 15*time.Second {
		t.Fatalf("startup heartbeat interval = %v, want 15s", startupHeartbeatInterval)
	}
}
