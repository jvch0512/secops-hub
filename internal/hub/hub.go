// Package hub stores recent alerts, correlates them into per-host incidents and fans them out to subscribers.
package hub

import (
	"sort"
	"sync"
	"time"

	"github.com/jvch0512/secops-hub/internal/sim"
)

const maxAlerts = 500

var weight = map[int]int{1: 1, 2: 3, 3: 6, 4: 10}

type Incident struct {
	Host     string    `json:"host"`
	Score    int       `json:"score"`
	Alerts   int       `json:"alerts"`
	Tactics  []string  `json:"tactics"` // distinct, in order of first appearance
	Last     time.Time `json:"last"`
	Critical bool      `json:"critical"`
	MaxSev   int       `json:"max_severity"`
}

type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Stats struct {
	Total      int        `json:"total"`
	Severity   [5]int     `json:"severity"` // index 1..4
	Tactics    []Count    `json:"tactics"`  // kill-chain order, zero counts included
	Techniques []Count    `json:"techniques"`
	Incidents  []Incident `json:"incidents"` // highest score first
	Critical   int        `json:"critical_incidents"`
}

type Hub struct {
	mu        sync.RWMutex
	alerts    []sim.Alert
	total     int
	sev       [5]int
	tactics   map[string]int
	tech      map[string]int
	incidents map[string]*Incident
	subs      map[chan sim.Alert]struct{}
}

func New() *Hub {
	return &Hub{tactics: map[string]int{}, tech: map[string]int{}, incidents: map[string]*Incident{}, subs: map[chan sim.Alert]struct{}{}}
}

// isCritical needs real signal: at least one high or critical alert, plus either a progressing chain
// (four distinct tactics) or a large accumulated score. Low-severity background noise alone never qualifies.
func isCritical(i *Incident) bool { return i.MaxSev >= 3 && (len(i.Tactics) >= 4 || i.Score >= 25) }

func (h *Hub) Add(a sim.Alert) {
	h.mu.Lock()
	h.alerts = append(h.alerts, a)
	if len(h.alerts) > maxAlerts {
		h.alerts = append([]sim.Alert(nil), h.alerts[len(h.alerts)-maxAlerts:]...)
	}
	h.total++
	if a.Severity >= 1 && a.Severity <= 4 {
		h.sev[a.Severity]++
	}
	h.tactics[a.Tactic]++
	h.tech[a.Technique]++
	inc := h.incidents[a.Host]
	if inc == nil {
		inc = &Incident{Host: a.Host}
		h.incidents[a.Host] = inc
	}
	inc.Alerts++
	inc.Score += weight[a.Severity]
	inc.Last = a.Time
	if a.Severity > inc.MaxSev {
		inc.MaxSev = a.Severity
	}
	seen := false
	for _, t := range inc.Tactics {
		if t == a.Tactic {
			seen = true
		}
	}
	if !seen {
		inc.Tactics = append(inc.Tactics, a.Tactic)
	}
	inc.Critical = isCritical(inc)
	for ch := range h.subs {
		select {
		case ch <- a:
		default: // slow consumer: drop instead of blocking the pipeline
		}
	}
	h.mu.Unlock()
}

// Subscribe returns a channel of new alerts and a cancel function.
func (h *Hub) Subscribe() (<-chan sim.Alert, func()) {
	ch := make(chan sim.Alert, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Recent returns up to n newest alerts, newest first.
func (h *Hub) Recent(n int) []sim.Alert {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if n <= 0 || n > len(h.alerts) {
		n = len(h.alerts)
	}
	out := make([]sim.Alert, 0, n)
	for i := len(h.alerts) - 1; i >= len(h.alerts)-n; i-- {
		out = append(out, h.alerts[i])
	}
	return out
}

func (h *Hub) Get(id int) (sim.Alert, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := len(h.alerts) - 1; i >= 0; i-- {
		if h.alerts[i].ID == id {
			return h.alerts[i], true
		}
	}
	return sim.Alert{}, false
}

func (h *Hub) IncidentFor(host string) (Incident, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if i, ok := h.incidents[host]; ok {
		return *i, true
	}
	return Incident{}, false
}

func (h *Hub) Stats() Stats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := Stats{Total: h.total, Severity: h.sev}
	for _, t := range sim.Tactics {
		s.Tactics = append(s.Tactics, Count{t, h.tactics[t]})
	}
	for id, n := range h.tech {
		s.Techniques = append(s.Techniques, Count{id + " " + sim.Catalog[id].Name, n})
	}
	sort.Slice(s.Techniques, func(i, j int) bool {
		if s.Techniques[i].Count != s.Techniques[j].Count {
			return s.Techniques[i].Count > s.Techniques[j].Count
		}
		return s.Techniques[i].Name < s.Techniques[j].Name
	})
	if len(s.Techniques) > 8 {
		s.Techniques = s.Techniques[:8]
	}
	for _, i := range h.incidents {
		c := *i
		c.Tactics = append([]string(nil), i.Tactics...)
		s.Incidents = append(s.Incidents, c)
		if c.Critical {
			s.Critical++
		}
	}
	sort.Slice(s.Incidents, func(i, j int) bool {
		if s.Incidents[i].Score != s.Incidents[j].Score {
			return s.Incidents[i].Score > s.Incidents[j].Score
		}
		return s.Incidents[i].Host < s.Incidents[j].Host
	})
	if len(s.Incidents) > 8 {
		s.Incidents = s.Incidents[:8]
	}
	return s
}
