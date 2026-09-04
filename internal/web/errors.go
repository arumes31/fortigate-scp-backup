package web

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
)

type errorData struct {
	Base      BaseData
	Code      int
	Title     string
	Message   string
	RequestID string
	BackURL   string
	RetryURL  string
}

func errorPageCopy(lang string, code int) (title, message string) {
	switch code {
	case http.StatusNotFound:
		return tr(lang, "error.not_found_title"), tr(lang, "error.not_found_message")
	case http.StatusMethodNotAllowed:
		return tr(lang, "error.method_title"), tr(lang, "error.method_message")
	default:
		return tr(lang, "error.internal_title"), tr(lang, "error.internal_message")
	}
}

// renderError renders a generic, localized recovery page while preserving the
// actual HTTP status. It accepts no internal error detail, which prevents a
// caller from accidentally exposing database errors, panic text, or stacks.
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, code int, retryable bool) {
	lang := langFromRequest(r)
	title, message := errorPageCopy(lang, code)
	requestID := middleware.GetReqID(r.Context())
	data := errorData{
		Base:      s.base(r, title, ""),
		Code:      code,
		Title:     title,
		Message:   message,
		RequestID: requestID,
		BackURL:   safeErrorBackPath(r),
	}
	if retryable && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		data.RetryURL = safeRequestURI(r)
	}

	p, ok := s.pages["error.html"]
	if !ok {
		http.Error(w, fallbackErrorText(message, requestID), code)
		return
	}
	var buf bytes.Buffer
	if err := p.render(&buf, data); err != nil {
		s.logger.Error("error page render failed", "reqid", requestID, "status", code, "err", err)
		http.Error(w, fallbackErrorText(message, requestID), code)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = buf.WriteTo(w)
}

func fallbackErrorText(message, requestID string) string {
	if requestID == "" {
		return message
	}
	return fmt.Sprintf("%s Request ID: %s", message, requestID)
}

func safeRequestURI(r *http.Request) string {
	uri := r.URL.RequestURI()
	if uri == "" || !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") || strings.HasPrefix(uri, "/\\") {
		return "/dashboard"
	}
	return uri
}

// safeErrorBackPath keeps only the path of a same-origin referrer. Queries are
// deliberately discarded so an error page never reflects tokens or filters.
func safeErrorBackPath(r *http.Request) string {
	const fallback = "/dashboard"
	raw := strings.TrimSpace(r.Referer())
	if raw == "" {
		return fallback
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return fallback
	}
	if ref.IsAbs() && !strings.EqualFold(ref.Host, r.Host) {
		return fallback
	}
	path := ref.EscapedPath()
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.HasPrefix(path, "/\\") || path == r.URL.EscapedPath() {
		return fallback
	}
	return path
}

// recoverer converts panics into the same safe 500 page. Panic details and the
// stack stay in the structured application log and share the page request ID.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				requestID := middleware.GetReqID(r.Context())
				w.Header().Set("X-Request-Id", requestID)
				s.logger.Error("http panic recovered",
					"reqid", requestID,
					"method", r.Method,
					"path", r.URL.Path,
					"panic", fmt.Sprint(recovered),
					"stack", string(debug.Stack()),
				)
				s.renderError(w, r, http.StatusInternalServerError, true)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusNotFound, false)
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusMethodNotAllowed, false)
}
