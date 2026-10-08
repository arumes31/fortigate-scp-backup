package database

import "testing"

func TestErrorReasonIsReadable(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{status: "Failed: connection timeout", want: "connection timeout"},
		{status: "Failed:   multi-stage failure", want: "multi-stage failure"},
		{status: "Failed:", want: "Backup failed without a reported reason."},
	}
	for _, tt := range tests {
		if got := backupFailureReason(tt.status); got != tt.want {
			t.Errorf("backupFailureReason(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}
