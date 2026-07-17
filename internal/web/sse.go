package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// sseHub fans out firewall status changes to connected Server-Sent-Events
// clients so the dashboard/list update live.
type sseHub struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
	// done is closed once on shutdown so streaming handlers return promptly
	// (http.Server.Shutdown does not cancel their request contexts).
	done     chan struct{}
	doneOnce sync.Once
}

func newSSEHub() *sseHub {
	return &sseHub{clients: make(map[chan string]struct{}), done: make(chan struct{})}
}

// shutdown signals all streaming handlers to return so graceful shutdown does
// not block on open SSE connections.
func (h *sseHub) shutdown() {
	h.doneOnce.Do(func() { close(h.done) })
}

func (h *sseHub) subscribe() chan string {
	ch := make(chan string, 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *sseHub) unsubscribe(ch chan string) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// broadcast fans one event out to every client. kind identifies the operation
// ("backup" status changes, or an operation lifecycle event: "analysis",
// "devicedata", "sshdiag", "audit", "live" with status "started"/"finished");
// consumers that only care about backups filter on it.
func (h *sseHub) broadcast(kind string, fwID int, status string) {
	// Marshal via encoding/json: fmt %q produces Go quoting (\xNN for control
	// or invalid-UTF-8 bytes) which is not valid JSON and makes the browser's
	// JSON.parse throw, silently dropping the status update.
	payload, err := json.Marshal(struct {
		Kind   string `json:"kind"`
		FwID   int    `json:"fw_id"`
		Status string `json:"status"`
	}{Kind: kind, FwID: fwID, Status: status})
	if err != nil {
		return
	}
	msg := string(payload)
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default: // drop for slow clients
		}
	}
}

// handleEvents streams status changes to the browser as SSE.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.hub.done:
			// Server is shutting down; end the stream so Shutdown can complete.
			return
		case msg := <-ch:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}
