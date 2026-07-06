package web

import (
	"fmt"
	"net/http"
	"sync"
)

// sseHub fans out firewall status changes to connected Server-Sent-Events
// clients so the dashboard/list update live.
type sseHub struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
}

func newSSEHub() *sseHub {
	return &sseHub{clients: make(map[chan string]struct{})}
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

func (h *sseHub) broadcast(fwID int, status string) {
	msg := fmt.Sprintf(`{"fw_id":%d,"status":%q}`, fwID, status)
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

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}
