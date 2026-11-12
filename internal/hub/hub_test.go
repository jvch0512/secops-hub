package hub

import (
	"testing"
	"time"

	"github.com/jvch0512/secops-hub/internal/sim"
)

func alert(id int, host, tactic string, sev int) sim.Alert {
	return sim.Alert{ID: id, Time: time.Unix(int64(id), 0).UTC(), Host: host, Tactic: tactic, Technique: "T1566", Severity: sev}
}

func TestIncidentCorrelationAndCritical(t *testing.T) {
	h := New()
	for i, tac := range []string{"Initial Access", "Execution", "Execution", "Persistence"} {
		h.Add(alert(i+1, "A", tac, 2))
	}
	inc, _ := h.IncidentFor("A")
	if len(inc.Tactics) != 3 || inc.Alerts != 4 || inc.Score != 12 {
		t.Fatalf("%+v", inc)
	}
	if inc.Critical {
		t.Fatal("three tactics and score 12 is not critical yet")
	}
	h.Add(alert(5, "A", "Credential Access", 2))
	if inc, _ = h.IncidentFor("A"); inc.Critical {
		t.Fatalf("four tactics of low-severity noise must not be critical: %+v", inc)
	}
	h.Add(alert(9, "A", "Credential Access", 4))
	if inc, _ = h.IncidentFor("A"); !inc.Critical || inc.MaxSev != 4 {
		t.Fatalf("four tactics plus a critical alert must be critical: %+v", inc)
	}
	h.Add(alert(6, "B", "Impact", 4))
	h.Add(alert(7, "B", "Impact", 4))
	h.Add(alert(8, "B", "Impact", 4))
	if inc, _ = h.IncidentFor("B"); !inc.Critical || len(inc.Tactics) != 1 {
		t.Fatalf("score 30 on one tactic is critical: %+v", inc)
	}
	if s := h.Stats(); s.Critical != 2 || s.Total != 9 || s.Incidents[0].Host != "B" {
		t.Fatalf("%+v", s)
	}
}

func TestRingBufferAndRecent(t *testing.T) {
	h := New()
	for i := 1; i <= maxAlerts+50; i++ {
		h.Add(alert(i, "A", "Execution", 1))
	}
	r := h.Recent(3)
	if len(r) != 3 || r[0].ID != maxAlerts+50 || r[2].ID != maxAlerts+48 {
		t.Fatalf("newest first expected: %+v", r)
	}
	if len(h.Recent(0)) != maxAlerts {
		t.Fatal("buffer must be capped")
	}
	if _, ok := h.Get(1); ok {
		t.Fatal("old alert should have aged out")
	}
	if a, ok := h.Get(maxAlerts + 50); !ok || a.ID != maxAlerts+50 {
		t.Fatal("recent alert must be found")
	}
	if h.Stats().Total != maxAlerts+50 {
		t.Fatal("total counts every alert, not just the buffer")
	}
}

func TestSubscribeBroadcastCancelAndSlowConsumer(t *testing.T) {
	h := New()
	ch, cancel := h.Subscribe()
	h.Add(alert(1, "A", "Execution", 1))
	if a := <-ch; a.ID != 1 {
		t.Fatal("subscriber should receive alerts")
	}
	for i := 2; i < 200; i++ { // far more than the channel capacity, nobody reading
		h.Add(alert(i, "A", "Execution", 1))
	}
	cancel()
	cancel() // idempotent
	h.Add(alert(300, "A", "Execution", 1))
	if h.Stats().Total != 200 {
		t.Fatalf("a slow consumer must never block the hub: %d", h.Stats().Total)
	}
}

func TestStatsTacticsInKillChainOrderAndTopTechniquesCapped(t *testing.T) {
	h := New()
	h.Add(alert(1, "A", "Impact", 4))
	s := h.Stats()
	if len(s.Tactics) != len(sim.Tactics) || s.Tactics[0].Name != "Initial Access" || s.Tactics[len(s.Tactics)-1].Count != 1 {
		t.Fatalf("%+v", s.Tactics)
	}
}
