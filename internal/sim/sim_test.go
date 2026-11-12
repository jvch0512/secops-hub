package sim

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestDeterministicForSameSeed(t *testing.T) {
	a, b := New(7, t0), New(7, t0)
	for i := 0; i < 300; i++ {
		if x, y := a.Next(), b.Next(); x != y {
			t.Fatalf("alert %d differs: %+v vs %+v", i, x, y)
		}
	}
	c := New(8, t0)
	same := true
	a = New(7, t0)
	for i := 0; i < 50; i++ {
		if a.Next() != c.Next() {
			same = false
		}
	}
	if same {
		t.Fatal("different seeds should give different streams")
	}
}

func TestAlertsAreWellFormed(t *testing.T) {
	g := New(1, t0)
	prev := t0
	for i := 1; i <= 500; i++ {
		a := g.Next()
		if a.ID != i || !a.Time.After(prev) {
			t.Fatalf("ids must be sequential and time must increase: %+v", a)
		}
		prev = a.Time
		tech, ok := Catalog[a.Technique]
		if !ok || a.Tactic != tech.Tactic || a.Severity < 1 || a.Severity > 4 {
			t.Fatalf("bad alert %+v", a)
		}
		if !strings.HasPrefix(a.SrcIP, "198.51.100.") && !strings.HasPrefix(a.SrcIP, "203.0.113.") && !strings.HasPrefix(a.SrcIP, "192.0.2.") {
			t.Fatalf("source IP must be from documentation ranges: %s", a.SrcIP)
		}
	}
}

func TestCampaignsFollowScenarioOrder(t *testing.T) {
	g := New(3, t0)
	byHost := map[string][]string{}
	for i := 0; i < 3000; i++ {
		if a := g.Next(); a.Scenario != "" {
			key := a.Host + "|" + a.Scenario + "|" + a.SrcIP
			byHost[key] = append(byHost[key], a.Technique)
		}
	}
	if len(byHost) == 0 {
		t.Fatal("expected campaigns")
	}
	for key, got := range byHost {
		scenario := strings.Split(key, "|")[1]
		want := Scenarios[scenario]
		for i, tech := range got {
			if i < len(want) && tech != want[i] {
				t.Fatalf("%s step %d: got %s want %s", key, i, tech, want[i])
			}
		}
	}
}

func TestCatalogCoversScenariosAndTactics(t *testing.T) {
	known := map[string]bool{}
	for _, tc := range Tactics {
		known[tc] = true
	}
	for name, steps := range Scenarios {
		for _, id := range steps {
			tech, ok := Catalog[id]
			if !ok || !known[tech.Tactic] {
				t.Fatalf("%s uses unknown technique or tactic %s", name, id)
			}
		}
	}
}
