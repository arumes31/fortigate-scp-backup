// Package webui owns FortiSafe's shared server-rendered presentation contract.
// It deliberately contains no session, database, scheduler, or extension
// dependencies; callers provide already-authorized presentation data.
package webui

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"reflect"
)

//go:embed templates/base.html
var shellFS embed.FS

// ErrPreRenderedHTML is returned when view data contains template.HTML.
// FortiSafe page data must stay typed and auto-escaped; trusted markup belongs
// in templates, not in strings assembled by handlers or extensions.
var ErrPreRenderedHTML = errors.New("webui: pre-rendered HTML is not accepted")

// BaseData is the stable presentation-only context shared by authenticated
// Core and extension pages. It intentionally contains no request, session,
// configuration, or persistence objects.
type BaseData struct {
	Title      string
	Username   string
	Lang       string
	IsRadius   bool
	Active     string
	ReturnTo   string
	Shell      ShellLabels
	Navigation []NavGroup
}

// ShellLabels contains the small set of localized strings owned by the shared
// authenticated shell. Page-specific language remains with each page.
type ShellLabels struct {
	Product           string
	SkipToContent     string
	PrimaryNavigation string
	Utilities         string
	LiveStatus        string
	Connecting        string
	Connected         string
	Reconnecting      string
	Unavailable       string
	Language          string
	TimeDisplay       string
	UTC               string
	BrowserTime       string
	Local             string
	Account           string
	ChangePassword    string
	Logout            string
}

// ShellText returns the authenticated shell labels for a supported language.
// English is the stable fallback for unknown or missing language values.
func ShellText(lang string) ShellLabels {
	if lang == "de" {
		return ShellLabels{
			Product: "Betriebskonsole", SkipToContent: "Zum Inhalt springen", PrimaryNavigation: "Primärnavigation",
			Utilities: "Hilfsfunktionen", LiveStatus: "Live-Status", Connecting: "Verbindet",
			Connected: "Verbunden", Reconnecting: "Verbindung unterbrochen", Unavailable: "Nicht verfügbar",
			Language: "Sprache", TimeDisplay: "Zeitanzeige", UTC: "UTC", BrowserTime: "Browserzeit", Local: "Lokal",
			Account: "Konto", ChangePassword: "Passwort ändern", Logout: "Abmelden",
		}
	}
	return ShellLabels{
		Product: "Operations console", SkipToContent: "Skip to content", PrimaryNavigation: "Primary navigation",
		Utilities: "Utilities", LiveStatus: "Live status", Connecting: "Connecting",
		Connected: "Connected", Reconnecting: "Connection interrupted", Unavailable: "Unavailable",
		Language: "Language", TimeDisplay: "Time display", UTC: "UTC", BrowserTime: "Browser time", Local: "Local",
		Account: "Account", ChangePassword: "Change password", Logout: "Log out",
	}
}

// Renderer owns one isolated shell-plus-page template set. A Renderer is safe
// for concurrent execution after ParsePage returns.
type Renderer struct {
	template *template.Template
}

// ParsePage combines the embedded FortiSafe shell with exactly one page from
// pageFS. A fresh template set is created on every call, so sibling extensions
// may use the same page filename and block names without collisions.
func ParsePage(pageFS fs.FS, pagePath string, funcs template.FuncMap) (*Renderer, error) {
	if pageFS == nil {
		return nil, errors.New("webui: page filesystem is required")
	}
	if pagePath == "" {
		return nil, errors.New("webui: page path is required")
	}
	shell, err := fs.ReadFile(shellFS, "templates/base.html")
	if err != nil {
		return nil, fmt.Errorf("webui: read shell: %w", err)
	}
	page, err := fs.ReadFile(pageFS, pagePath)
	if err != nil {
		return nil, fmt.Errorf("webui: read page %q: %w", pagePath, err)
	}

	templateFuncs := template.FuncMap{"L": Localize}
	for name, function := range funcs {
		templateFuncs[name] = function
	}
	parsed := template.New("webui").Funcs(templateFuncs)
	if _, err := parsed.Parse(string(shell)); err != nil {
		return nil, fmt.Errorf("webui: parse shell: %w", err)
	}
	if _, err := parsed.Parse(string(page)); err != nil {
		return nil, fmt.Errorf("webui: parse page %q: %w", pagePath, err)
	}
	return &Renderer{template: parsed}, nil
}

// Render executes into a private buffer and copies to destination only after a
// complete successful render. Callers therefore never receive partial HTML.
func (r *Renderer) Render(destination io.Writer, data any) error {
	if r == nil || r.template == nil {
		return errors.New("webui: renderer is not initialized")
	}
	if destination == nil {
		return errors.New("webui: render destination is required")
	}
	if containsPreRenderedHTML(reflect.ValueOf(data), make(map[visit]struct{})) {
		return ErrPreRenderedHTML
	}
	var output bytes.Buffer
	if err := r.template.ExecuteTemplate(&output, "webui.shell", data); err != nil {
		return fmt.Errorf("webui: execute page: %w", err)
	}
	if _, err := output.WriteTo(destination); err != nil {
		return fmt.Errorf("webui: write page: %w", err)
	}
	return nil
}

// RenderHTTP is the HTTP boundary for a successfully parsed page. Headers and
// body are committed only after template execution succeeds.
func (r *Renderer) RenderHTTP(w http.ResponseWriter, data any) error {
	var output bytes.Buffer
	if err := r.Render(&output, data); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := output.WriteTo(w)
	return err
}

type visit struct {
	typ reflect.Type
	ptr uintptr
}

var preRenderedHTMLType = reflect.TypeOf(template.HTML(""))

func containsPreRenderedHTML(value reflect.Value, seen map[visit]struct{}) bool {
	if !value.IsValid() {
		return false
	}
	if value.Type() == preRenderedHTMLType {
		return true
	}

	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return false
		}
		return containsPreRenderedHTML(value.Elem(), seen)
	case reflect.Pointer:
		if value.IsNil() || alreadyVisited(value, seen) {
			return false
		}
		return containsPreRenderedHTML(value.Elem(), seen)
	case reflect.Map:
		if value.IsNil() || alreadyVisited(value, seen) {
			return false
		}
		iterator := value.MapRange()
		for iterator.Next() {
			if containsPreRenderedHTML(iterator.Key(), seen) || containsPreRenderedHTML(iterator.Value(), seen) {
				return true
			}
		}
	case reflect.Slice:
		if value.IsNil() || alreadyVisited(value, seen) {
			return false
		}
		for index := 0; index < value.Len(); index++ {
			if containsPreRenderedHTML(value.Index(index), seen) {
				return true
			}
		}
	case reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if containsPreRenderedHTML(value.Index(index), seen) {
				return true
			}
		}
	case reflect.Struct:
		typ := value.Type()
		for index := 0; index < value.NumField(); index++ {
			if typ.Field(index).PkgPath != "" {
				continue
			}
			if containsPreRenderedHTML(value.Field(index), seen) {
				return true
			}
		}
	}
	return false
}

func alreadyVisited(value reflect.Value, seen map[visit]struct{}) bool {
	key := visit{typ: value.Type(), ptr: value.Pointer()}
	if _, ok := seen[key]; ok {
		return true
	}
	seen[key] = struct{}{}
	return false
}
