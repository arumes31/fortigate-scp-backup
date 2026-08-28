package security

import (
	"path/filepath"
	"testing"
)

func TestJoinWithin(t *testing.T) {
	root := t.TempDir()
	path, err := JoinWithin(root, "12/backup.conf")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "12", "backup.conf"); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	for _, unsafe := range []string{
		"../secret",
		"12/../../secret",
		"/etc/passwd",
		`C:\\Windows\\win.ini`,
		`C:/Windows/win.ini`,
		`C:Windows\\win.ini`,
		`\\\\server\\share\\backup.conf`,
	} {
		if _, err := JoinWithin(root, unsafe); err == nil {
			t.Errorf("unsafe path %q accepted", unsafe)
		}
	}
}
