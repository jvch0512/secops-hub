package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jvch0512/secops-hub/internal/analyst"
	"github.com/jvch0512/secops-hub/internal/hub"
	"github.com/jvch0512/secops-hub/internal/sim"
)

func setup(t *testing.T) (*httptest.Server, *hub.Hub) {
	t.Helper()
	h := hub.New()
	g := sim.New(1, time.Now().UTC())
	for i := 0; i < 30; i++ {
		h.Add(g.Next())
	}
	ts := httptest.NewServer((&Server{Hub: h, Analyst: &analyst.Client{}}).Handler())
	t.Cleanup(ts.Close)
	return ts, h
}

func TestStaticUIAndSecurityHeaders(t *testing.T) {
	ts, _ := setup(t)
	for _, p := range []string{"/", "/app.js", "/style.css"} {
		r, err := http.Get(ts.URL + p)
		if err != nil || r.StatusCode != 200 {
			t.Fatalf("%s: %v %d", p, err, r.StatusCode)
		}
		if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || r.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s missing security headers: %v", p, r.Header)
		}
	}
}

func TestStatsAndAlertsAPI(t *testing.T) {
	ts, _ := setup(t)
	var s hub.Stats
	r, _ := http.Get(ts.URL + "/api/stats")
	if json.NewDecoder(r.Body).Decode(&s) != nil || s.Total != 30 || len(s.Tactics) != 12 {
		t.Fatalf("%+v", s)
	}
	var as []sim.Alert
	r, _ = http.Get(ts.URL + "/api/alerts?limit=5")
	json.NewDecoder(r.Body).Decode(&as)
	if len(as) != 5 || as[0].ID != 30 {
		t.Fatalf("newest first: %+v", as)
	}
	r, _ = http.Get(ts.URL + "/api/alerts?limit=99999")
	as = nil
	json.NewDecoder(r.Body).Decode(&as)
	if len(as) != 30 {
		t.Fatalf("limit above cap falls back to default and returns what exists: %d", len(as))
	}
}

func TestExplainEndpoint(t *testing.T) {
	ts, _ := setup(t)
	post := func(q string) *http.Response {
		r, err := http.Post(ts.URL+"/api/explain"+q, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	var a analyst.Analysis
	r := post("?id=30")
	if r.StatusCode != 200 || json.NewDecoder(r.Body).Decode(&a) != nil || a.Source != "offline" || len(a.Actions) == 0 {
		t.Fatalf("%d %+v", r.StatusCode, a)
	}
	if c := post("?id=999999").StatusCode; c != 404 {
		t.Errorf("unknown id: %d", c)
	}
	if c := post("?id=abc").StatusCode; c != 400 {
		t.Errorf("bad id: %d", c)
	}
	if r, _ := http.Get(ts.URL + "/api/explain?id=1"); r.StatusCode != 405 {
		t.Errorf("GET must be refused: %d", r.StatusCode)
	}
}

func TestSSEStreamsNewAlerts(t *testing.T) {
	ts, h := setup(t)
	r, err := http.Get(ts.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if ct := r.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	sc := bufio.NewScanner(r.Body)
	done := make(chan string, 1)
	go func() {
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data: ") {
				done <- strings.TrimPrefix(sc.Text(), "data: ")
				return
			}
		}
	}()
	time.Sleep(100 * time.Millisecond) // let the handler subscribe
	h.Add(sim.Alert{ID: 777, Host: "H", Tactic: "Impact", Technique: "T1486", Severity: 4, Time: time.Now()})
	select {
	case line := <-done:
		var a sim.Alert
		if json.Unmarshal([]byte(line), &a) != nil || a.ID != 777 {
			t.Fatalf("%s", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event received")
	}
}
