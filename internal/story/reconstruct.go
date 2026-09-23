package story

import "time"

type Phase string

const (
	Recon       Phase = "recon"
	Scan        Phase = "scan"
	BruteForce  Phase = "bruteforce"
	Injection   Phase = "injection"
	Exfil       Phase = "exfil"
	Persistence Phase = "persistence"
)

type TimelineEvent struct {
	Timestamp time.Time     `json:"timestamp"`
	Method    string        `json:"method"`
	Path      string        `json:"path"`
	Status    int           `json:"status"`
	Action    string        `json:"action"`
	Reason    string        `json:"reason"`
	Latency   time.Duration `json:"latency_ns"`
	Phase     Phase         `json:"phase,omitempty"`
}
type RuleMatch struct {
	RuleID    string    `json:"rule_id"`
	Category  string    `json:"category"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}
type Story struct {
	ID              string          `json:"id"`
	AttackerIP      string          `json:"attacker_ip"`
	UserAgent       string          `json:"user_agent"`
	JA3Fingerprint  string          `json:"ja3_fingerprint"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastSeen        time.Time       `json:"last_seen"`
	TotalRequests   int             `json:"total_requests"`
	BlockedRequests int             `json:"blocked_requests"`
	Phases          []Phase         `json:"phases"`
	ThreatScore     int             `json:"threat_score"`
	Verdict         string          `json:"verdict"`
	Timeline        []TimelineEvent `json:"timeline"`
	RuleMatches     []RuleMatch     `json:"rule_matches"`
	FalsePositive   bool            `json:"false_positive"`
}
type Observation struct {
	IP, UserAgent, JA3, Method, Path, Action, Reason, Category, Severity string
	Status, ResponseBytes                                                int
	TorVPN                                                               bool
	Latency                                                              time.Duration
	At                                                                   time.Time
}
