package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// JoinWithin resolves a relative path beneath root and rejects absolute,
// volume-qualified, parent-traversal, and existing symlink-escape paths.
func JoinWithin(root, relative string) (string, error) {
	if relative == "" {
		return "", errors.New("path is empty")
	}
	native := filepath.FromSlash(relative)
	if filepath.IsAbs(native) || filepath.VolumeName(native) != "" ||
		strings.HasPrefix(relative, "/") || strings.HasPrefix(relative, `\`) ||
		hasWindowsVolumePrefix(relative) {
		return "", errors.New("absolute path is not allowed")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	candidate, err := filepath.Abs(filepath.Join(rootAbs, native))
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	if !isWithin(rootAbs, candidate) {
		return "", errors.New("path escapes configured root")
	}

	rootReal, rootErr := filepath.EvalSymlinks(rootAbs)
	candidateReal, candidateErr := filepath.EvalSymlinks(candidate)
	if rootErr == nil && candidateErr == nil && !isWithin(rootReal, candidateReal) {
		return "", errors.New("symlink path escapes configured root")
	}
	if candidateErr != nil && !errors.Is(candidateErr, os.ErrNotExist) {
		return "", fmt.Errorf("resolve symlink path: %w", candidateErr)
	}
	return candidate, nil
}

// hasWindowsVolumePrefix rejects drive-relative and drive-absolute paths even
// when validation runs on a non-Windows host.
func hasWindowsVolumePrefix(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	letter := path[0]
	return (letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z')
}

func isWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
