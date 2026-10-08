package security

import (
	"os"
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

func TestJoinWithinRejectsRootItself(t *testing.T) {
	root := t.TempDir()
	for _, relative := range []string{".", "child/.."} {
		if _, err := JoinWithin(root, relative); err == nil {
			t.Errorf("root-resolving path %q accepted", relative)
		}
	}
}

func TestJoinWithinRejectsMissingDescendantThroughEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	if _, err := JoinWithin(root, "escape/missing/backup.conf"); err == nil {
		t.Fatal("missing descendant below an escaping symlink was accepted")
	}
}

func TestJoinWithinRejectsSymlinkResolvingToRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(root, filepath.Join(root, "self")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	if _, err := JoinWithin(root, "self"); err == nil {
		t.Fatal("path resolving to the configured root was accepted")
	}
}

func TestJoinWithinAllowsMissingDescendantThroughInternalSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(root, "inside")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	if _, err := JoinWithin(root, "inside/missing/backup.conf"); err != nil {
		t.Fatalf("safe missing descendant rejected: %v", err)
	}
}
