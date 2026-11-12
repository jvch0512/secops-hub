// Package server exposes the hub over HTTP: a REST API, a Server-Sent Events stream and the embedded web UI.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/jvch0512/secops-hub/internal/analyst"
	"github.com/jvch0512/secops-hub/internal/hub"
)

//go:embed static
var static embed.FS

type Server struct {
	Hub     *hub.Hub
	Analyst *analyst.Client // may be nil: offline analyst only
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/stats", s.stats)
	mux.HandleFunc("/api/alerts", s.alerts)
	mux.HandleFunc("/api/explain", s.explain)
	mux.HandleFunc("/events", s.events)
	return secure(mux)
}

// secure sets strict browser security headers. The UI uses no inline script or style and no external origin.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Hub.Stats()) }

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 200 {
		n = 50
	}
	writeJSON(w, s.Hub.Recent(n))
}

func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "id must be an integer", http.StatusBadRequest)
		return
	}
	a, ok := s.Hub.Get(id)
	if !ok {
		http.Error(w, "alert not found (it may have aged out of the buffer)", http.StatusNotFound)
		return
	}
	inc, _ := s.Hub.IncidentFor(a.Host)
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	writeJSON(w, s.Analyst.Explain(ctx, a, inc))
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	ch, cancel := s.Hub.Subscribe()
	defer cancel()
	w.Write([]byte(": connected\n\n"))
	fl.Flush()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			w.Write([]byte(": keepalive\n\n"))
			fl.Flush()
		case a, open := <-ch:
			if !open {
				return
			}
			b, _ := json.Marshal(a)
			w.Write([]byte("data: "))
			w.Write(b)
			w.Write([]byte("\n\n"))
			fl.Flush()
		}
	}
}
