package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var (
	scriptTagPattern      = regexp.MustCompile(`(?is)<script\b([^>]*)>`)
	scriptSourcePattern   = regexp.MustCompile(`(?i)\bsrc\s*=`)
	styleElementPattern   = regexp.MustCompile(`(?i)<style\b`)
	eventAttributePattern = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	javascriptURLPattern  = regexp.MustCompile(`(?i)\b(?:href|src|action)\s*=\s*["']\s*javascript:`)
	dynamicCodePattern    = regexp.MustCompile(`(?m)(?:\beval\s*\(|\bnew\s+Function\s*\(|\bdocument\.write\s*\(|\.insertAdjacentHTML\s*\()`)
	directHTMLSinkPattern = regexp.MustCompile(`(?m)\.innerHTML\s*=\s*(?:response(?:Text)?|data(?:\.|\s*;))`)
)

func TestStaticBrowserSecurityContract(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate security contract source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))

	walkSecurityFiles(t, root, func(path string, contents []byte) {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		source := string(contents)
		switch strings.ToLower(filepath.Ext(path)) {
		case ".html":
			for _, match := range scriptTagPattern.FindAllStringSubmatch(source, -1) {
				if !scriptSourcePattern.MatchString(match[1]) {
					t.Errorf("%s contains an inline script element", relative)
				}
			}
			if styleElementPattern.MatchString(source) {
				t.Errorf("%s contains an inline style element", relative)
			}
			if eventAttributePattern.MatchString(source) {
				t.Errorf("%s contains an inline event handler", relative)
			}
			if javascriptURLPattern.MatchString(source) {
				t.Errorf("%s contains a javascript: URL", relative)
			}
		case ".js":
			if strings.HasSuffix(strings.ToLower(path), ".min.js") {
				return
			}
			if dynamicCodePattern.MatchString(source) {
				t.Errorf("%s contains dynamic code evaluation or HTML insertion", relative)
			}
			if directHTMLSinkPattern.MatchString(source) {
				t.Errorf("%s assigns an untrusted response value directly to innerHTML", relative)
			}
		}
	})
}

func walkSecurityFiles(t *testing.T, root string, inspect func(string, []byte)) {
	t.Helper()
	for _, directory := range []string{
		filepath.Join(root, "internal", "web", "templates"),
		filepath.Join(root, "internal", "webui", "templates"),
		filepath.Join(root, "internal", "web", "static"),
		filepath.Join(root, "extensions"),
	} {
		err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			extension := strings.ToLower(filepath.Ext(path))
			if extension != ".html" && extension != ".js" {
				return nil
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			inspect(path, contents)
			return nil
		})
		if err != nil {
			t.Fatalf("scan browser security files under %s: %v", directory, err)
		}
	}
}
