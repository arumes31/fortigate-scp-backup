package web

import (
	"bytes"
	"net/http"
)

type errorData struct {
	Base    BaseData
	Code    int
	Message string
}

// renderError renders a styled error page with the given status code. It falls
// back to plain text if the template is unavailable.
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	p, ok := s.pages["error.html"]
	if !ok {
		http.Error(w, msg, code)
		return
	}
	data := errorData{Base: s.base(r, "Error", ""), Code: code, Message: msg}
	var buf bytes.Buffer
	if err := p.t.ExecuteTemplate(&buf, p.exec, data); err != nil {
		http.Error(w, msg, code)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = buf.WriteTo(w)
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusNotFound, "The page you requested was not found.")
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusMethodNotAllowed, "That method is not allowed here.")
}
