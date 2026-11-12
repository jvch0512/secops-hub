package analyst

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jvch0512/secops-hub/internal/hub"
	"github.com/jvch0512/secops-hub/internal/sim"
)

var a1 = sim.Alert{ID: 1, Host: "WS-1", User: "bob", SrcIP: "203.0.113.9", Technique: "T1003", Name: "OS Credential Dumping", Tactic: "Credential Access", Severity: 4, Title: "LSASS read"}

func TestOfflineExplainUsesKnowledgeBaseAndContext(t *testing.T) {
	a := Explain(a1, hub.Incident{})
	if a.Source != "offline" || !strings.Contains(a.Summary, "WS-1") || !strings.Contains(a.Summary, "Critical") || len(a.Actions) < 3 {
		t.Fatalf("%+v", a)
	}
	b := Explain(a1, hub.Incident{Tactics: []string{"Initial Access", "Execution", "Credential Access"}})
	if b.Confidence != "high" || !strings.Contains(b.Why, "progressing attack") {
		t.Fatalf("multi-tactic hosts should raise confidence: %+v", b)
	}
	u := Explain(sim.Alert{Technique: "T9999", Severity: 9}, hub.Incident{})
	if len(u.Actions) == 0 || !strings.Contains(u.Summary, "Critical") {
		t.Fatalf("unknown techniques and out-of-range severity must not panic: %+v", u)
	}
}

func fake(t *testing.T, status int, reply string, seen *http.Request, body *string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = *r.Clone(context.Background())
		}
		if body != nil {
			b, _ := io.ReadAll(r.Body)
			*body = string(b)
		}
		w.WriteHeader(status)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	c := NewClient("test-key", "")
	c.BaseURL = srv.URL
	return c
}

func envelope(text string) string {
	b, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	return string(b)
}

func TestClaudeSuccessSendsExpectedRequest(t *testing.T) {
	var req http.Request
	var body string
	c := fake(t, 200, envelope("Here you go:\n```json\n{\"summary\":\"S\",\"why\":\"W\",\"actions\":[\"a\",\"b\",\"c\"],\"confidence\":\"high\"}\n```"), &req, &body)
	got := c.Explain(context.Background(), a1, hub.Incident{Host: "WS-1", Tactics: []string{"Execution"}})
	if got.Source != "claude" || got.Summary != "S" || len(got.Actions) != 3 {
		t.Fatalf("%+v", got)
	}
	if req.URL.Path != "/v1/messages" || req.Header.Get("x-api-key") != "test-key" || req.Header.Get("anthropic-version") == "" {
		t.Fatalf("bad request: %s %v", req.URL.Path, req.Header)
	}
	if !strings.Contains(body, "claude-sonnet-5-5") || !strings.Contains(body, "untrusted data") || !strings.Contains(body, "T1003") {
		t.Fatalf("body should carry model, the untrusted-data warning and the alert: %s", body)
	}
}

func TestClaudeFailuresFallBackOffline(t *testing.T) {
	for name, c := range map[string]*Client{
		"http error":  fake(t, 529, `{"error":"overloaded"}`, nil, nil),
		"bad json":    fake(t, 200, "not json", nil, nil),
		"no content":  fake(t, 200, `{"content":[]}`, nil, nil),
		"no object":   fake(t, 200, envelope("sorry, I cannot help"), nil, nil),
		"empty parts": fake(t, 200, envelope(`{"summary":"","actions":[]}`), nil, nil),
	} {
		got := c.Explain(context.Background(), a1, hub.Incident{})
		if !strings.HasPrefix(got.Source, "offline") || len(got.Actions) == 0 {
			t.Errorf("%s: %+v", name, got)
		}
	}
	dead := NewClient("k", "")
	dead.BaseURL = "http://127.0.0.1:1"
	if got := dead.Explain(context.Background(), a1, hub.Incident{}); !strings.HasPrefix(got.Source, "offline") {
		t.Errorf("unreachable API must fall back: %+v", got)
	}
}

func TestNoKeyOrNilClientIsOffline(t *testing.T) {
	var nilClient *Client
	if nilClient.Explain(context.Background(), a1, hub.Incident{}).Source != "offline" {
		t.Fatal("nil client")
	}
	if (&Client{}).Explain(context.Background(), a1, hub.Incident{}).Source != "offline" {
		t.Fatal("empty key must never call the network")
	}
}
