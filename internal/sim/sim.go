// Package sim generates a deterministic stream of synthetic security alerts that follow realistic
// attack chains mapped to MITRE ATT&CK. All hosts, users and addresses are fictional
// (IPs come from the RFC 5737 documentation ranges).
package sim

import (
	"fmt"
	"math/rand"
	"time"
)

// Tactics in kill-chain order.
var Tactics = []string{
	"Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
	"Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
}

type Technique struct {
	ID       string
	Name     string
	Tactic   string
	Severity int // 1 low .. 4 critical
	Title    string
}

var Catalog = map[string]Technique{
	"T1566": {"T1566", "Phishing", "Initial Access", 2, "Suspicious attachment opened from external sender"},
	"T1190": {"T1190", "Exploit Public-Facing Application", "Initial Access", 3, "Exploit attempt against public web application"},
	"T1110": {"T1110", "Brute Force", "Credential Access", 2, "Repeated failed logons from a single source"},
	"T1059": {"T1059", "Command and Scripting Interpreter", "Execution", 3, "Encoded PowerShell launched by Office process"},
	"T1053": {"T1053", "Scheduled Task/Job", "Persistence", 2, "New scheduled task created by non-admin process"},
	"T1547": {"T1547", "Boot or Logon Autostart Execution", "Persistence", 2, "Run key modified for autostart"},
	"T1068": {"T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 3, "Kernel driver loaded after local exploit pattern"},
	"T1055": {"T1055", "Process Injection", "Defense Evasion", 3, "Remote thread created in a trusted system process"},
	"T1003": {"T1003", "OS Credential Dumping", "Credential Access", 4, "LSASS memory read by unsigned process"},
	"T1087": {"T1087", "Account Discovery", "Discovery", 1, "Burst of directory enumeration queries"},
	"T1021": {"T1021", "Remote Services", "Lateral Movement", 3, "Admin share logon followed by remote service creation"},
	"T1560": {"T1560", "Archive Collected Data", "Collection", 2, "Large archive created in a user temp folder"},
	"T1071": {"T1071", "Application Layer Protocol", "Command and Control", 3, "Periodic HTTPS beaconing to rare domain"},
	"T1041": {"T1041", "Exfiltration Over C2 Channel", "Exfiltration", 4, "Unusual outbound data volume to rare destination"},
	"T1486": {"T1486", "Data Encrypted for Impact", "Impact", 4, "Mass file rename with new extension"},
}

// Scenarios are attack chains. Each is a list of technique IDs executed on one host.
var Scenarios = map[string][]string{
	"phishing-to-ransomware": {"T1566", "T1059", "T1547", "T1003", "T1087", "T1021", "T1486"},
	"web-exploit-to-exfil":   {"T1190", "T1059", "T1068", "T1055", "T1560", "T1071", "T1041"},
	"credential-stuffing":    {"T1110", "T1087", "T1021"},
}

var scenarioOrder = []string{"phishing-to-ransomware", "web-exploit-to-exfil", "credential-stuffing"}

type Alert struct {
	ID        int       `json:"id"`
	Time      time.Time `json:"time"`
	Host      string    `json:"host"`
	User      string    `json:"user"`
	SrcIP     string    `json:"src_ip"`
	Technique string    `json:"technique"`
	Name      string    `json:"technique_name"`
	Tactic    string    `json:"tactic"`
	Severity  int       `json:"severity"`
	Title     string    `json:"title"`
	Scenario  string    `json:"scenario,omitempty"`
}

type campaign struct {
	host, user, src, scenario string
	pos                       int
}

type Generator struct {
	rng    *rand.Rand
	now    time.Time
	id     int
	active []*campaign
	hosts  []string
	users  []string
}

var hostNames = []string{"WS-FIN-014", "WS-HR-007", "WS-DEV-031", "SRV-WEB-01", "SRV-DB-02", "SRV-FILE-03", "WS-EXEC-002", "SRV-AD-01", "WS-OPS-022", "SRV-MAIL-01"}
var userNames = []string{"mrodriguez", "jsilva", "akim", "lnovak", "pchen", "svc-backup", "tmueller", "rcosta"}
var srcRanges = []string{"198.51.100.", "203.0.113.", "192.0.2."}

func New(seed int64, start time.Time) *Generator {
	return &Generator{rng: rand.New(rand.NewSource(seed)), now: start, hosts: hostNames, users: userNames}
}

func (g *Generator) pick(s []string) string { return s[g.rng.Intn(len(s))] }

func (g *Generator) ip() string {
	return fmt.Sprintf("%s%d", srcRanges[g.rng.Intn(len(srcRanges))], 1+g.rng.Intn(254))
}

// Next returns the next alert. About one in four alerts advances (or starts) an attack chain; the rest is background noise.
func (g *Generator) Next() Alert {
	g.now = g.now.Add(time.Duration(2+g.rng.Intn(25)) * time.Second)
	g.id++
	var tech Technique
	var c *campaign
	switch r := g.rng.Float64(); {
	case r < 0.25 && len(g.active) > 0:
		c = g.active[g.rng.Intn(len(g.active))]
	case r < 0.32 && len(g.active) < 3:
		c = &campaign{host: g.pick(g.hosts), user: g.pick(g.users), src: g.ip(), scenario: scenarioOrder[g.rng.Intn(len(scenarioOrder))]}
		g.active = append(g.active, c)
	}
	a := Alert{ID: g.id, Time: g.now}
	if c != nil {
		steps := Scenarios[c.scenario]
		tech = Catalog[steps[c.pos]]
		a.Host, a.User, a.SrcIP, a.Scenario = c.host, c.user, c.src, c.scenario
		c.pos++
		if c.pos >= len(steps) {
			for i, x := range g.active {
				if x == c {
					g.active = append(g.active[:i], g.active[i+1:]...)
					break
				}
			}
		}
	} else {
		noise := []string{"T1087", "T1110", "T1053", "T1547"}
		tech = Catalog[noise[g.rng.Intn(len(noise))]]
		tech.Severity = 1 + g.rng.Intn(2) // background activity is low or medium
		a.Host, a.User, a.SrcIP = g.pick(g.hosts), g.pick(g.users), g.ip()
	}
	a.Technique, a.Name, a.Tactic, a.Severity, a.Title = tech.ID, tech.Name, tech.Tactic, tech.Severity, tech.Title
	return a
}
