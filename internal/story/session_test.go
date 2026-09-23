package story

import (
	"testing"
	"time"

	"github.com/mohdsaad0786/EpiLog/internal/events"
)

type memoryWriter struct{ items []Story }

func (writer *memoryWriter) Save(item Story) error {
	writer.items = append(writer.items, item)
	return nil
}
func TestReconstruction(t *testing.T) {
	writer := &memoryWriter{}
	engine := NewEngine(writer, events.NewMemory(), 5*time.Minute, 86, 24*time.Hour)
	now := time.Now()
	var result Story
	for index := 0; index < 3; index++ {
		result = engine.Observe(Observation{IP: "203.0.113.10", UserAgent: "attacker", At: now.Add(time.Duration(index) * time.Second), Path: "/admin/login", Method: "POST", Status: 403, Action: "blocked", Reason: "auth", Severity: "medium"})
	}
	result = engine.Observe(Observation{IP: "203.0.113.10", UserAgent: "attacker", At: now.Add(3 * time.Second), Path: "/?id=1'", Method: "GET", Status: 403, Action: "blocked", Reason: "sqli-001", Category: "sqli", Severity: "critical"})
	if result.TotalRequests != 4 || result.BlockedRequests != 4 {
		t.Fatalf("bad counters: %+v", result)
	}
	if result.ThreatScore < 86 || !engine.IsBlocked("203.0.113.10") {
		t.Fatalf("expected auto block, got %+v", result)
	}
	if len(writer.items) == 0 {
		t.Fatal("blocked session not saved")
	}
	if len(result.Phases) < 2 {
		t.Fatalf("expected recon and brute force: %+v", result.Phases)
	}
	engine.Close()
}
func BenchmarkObserve(b *testing.B) {
	engine := NewEngine(nil, events.NewMemory(), 5*time.Minute, 86, time.Hour)
	b.ResetTimer()
	for range b.N {
		engine.Observe(Observation{IP: "203.0.113.10", UserAgent: "bench", Method: "GET", Path: "/", Status: 200, Action: "allowed"})
	}
}
