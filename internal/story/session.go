package story

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/mohdsaad0786/EpiLog/internal/events"
)

type Writer interface{ Save(Story) error }
type session struct {
	story     Story
	touched   time.Time
	torVPN    bool
	phaseSeen map[Phase]time.Time
}
type Engine struct {
	mu        sync.Mutex
	sessions  map[string]*session
	blocks    map[string]time.Time
	writer    Writer
	bus       events.Bus
	window    time.Duration
	threshold int
	duration  time.Duration
	now       func() time.Time
}

func NewEngine(writer Writer, bus events.Bus, window time.Duration, threshold int, duration time.Duration) *Engine {
	return &Engine{sessions: make(map[string]*session), blocks: make(map[string]time.Time), writer: writer, bus: bus, window: window, threshold: threshold, duration: duration, now: time.Now}
}

func (engine *Engine) Observe(observation Observation) Story {
	if observation.At.IsZero() {
		observation.At = engine.now()
	}
	key := sha256.Sum256([]byte(observation.IP + "\x00" + observation.UserAgent + "\x00" + observation.JA3))
	identity := hex.EncodeToString(key[:12])
	engine.mu.Lock()
	item := engine.sessions[identity]
	if item == nil || observation.At.Sub(item.touched) > engine.window {
		if item != nil {
			engine.persist(item.story)
		}
		if len(engine.sessions) >= 10000 {
			engine.evictOldest()
		}
		item = &session{story: Story{ID: identity + "-" + observation.At.UTC().Format("20060102T150405.000000000"), AttackerIP: observation.IP, UserAgent: observation.UserAgent, JA3Fingerprint: observation.JA3, FirstSeen: observation.At}, phaseSeen: make(map[Phase]time.Time)}
		engine.sessions[identity] = item
	}
	item.touched, item.torVPN = observation.At, item.torVPN || observation.TorVPN
	current := &item.story
	current.LastSeen = observation.At
	current.TotalRequests++
	if observation.Action == "blocked" {
		current.BlockedRequests++
	}
	if observation.Severity != "" {
		current.RuleMatches = append(current.RuleMatches, RuleMatch{observation.Reason, observation.Category, observation.Severity, observation.At})
	}
	if len(current.RuleMatches) > 500 {
		current.RuleMatches = current.RuleMatches[len(current.RuleMatches)-500:]
	}
	phaseList := detectPhases(current.Timeline, observation)
	var primary Phase
	if len(phaseList) > 0 {
		primary = phaseList[len(phaseList)-1]
	}
	for _, phase := range phaseList {
		item.phaseSeen[phase] = observation.At
	}
	current.Phases = current.Phases[:0]
	for _, phase := range []Phase{Recon, Scan, BruteForce, Injection, Exfil, Persistence} {
		if seen, ok := item.phaseSeen[phase]; ok {
			if observation.At.Sub(seen) <= 10*time.Minute {
				current.Phases = append(current.Phases, phase)
			} else {
				delete(item.phaseSeen, phase)
			}
		}
	}
	current.Timeline = append(current.Timeline, TimelineEvent{observation.At, observation.Method, observation.Path, observation.Status, observation.Action, observation.Reason, observation.Latency, primary})
	if len(current.Timeline) > 500 {
		current.Timeline = current.Timeline[len(current.Timeline)-500:]
	}
	current.ThreatScore, current.Verdict = score(*current, item.torVPN)
	if current.ThreatScore >= engine.threshold {
		engine.blocks[observation.IP] = observation.At.Add(engine.duration)
	}
	result := clone(*current)
	engine.mu.Unlock()
	if result.ThreatScore >= engine.threshold {
		engine.persistBlock(observation.IP, observation.At.Add(engine.duration), "critical")
	}
	if observation.Action == "blocked" || result.Verdict == "critical" {
		engine.persist(result)
	}
	engine.bus.Publish(events.Event{Topic: "story", Data: result})
	return result
}

func clone(story Story) Story {
	story.Timeline = append([]TimelineEvent(nil), story.Timeline...)
	story.Phases = append([]Phase(nil), story.Phases...)
	story.RuleMatches = append([]RuleMatch(nil), story.RuleMatches...)
	return story
}
func (engine *Engine) persist(story Story) {
	if engine.writer != nil {
		if err := engine.writer.Save(story); err != nil {
			slog.Error("persist attack story", "error", err)
		}
	}
}
func (engine *Engine) evictOldest() {
	var oldest string
	var seen time.Time
	for key, item := range engine.sessions {
		if oldest == "" || item.touched.Before(seen) {
			oldest, seen = key, item.touched
		}
	}
	if oldest != "" {
		engine.persist(engine.sessions[oldest].story)
		delete(engine.sessions, oldest)
	}
}
func (engine *Engine) Sweep() {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	now := engine.now()
	for key, item := range engine.sessions {
		if now.Sub(item.touched) > engine.window {
			engine.persist(item.story)
			delete(engine.sessions, key)
		}
	}
	for ip, until := range engine.blocks {
		if now.After(until) {
			delete(engine.blocks, ip)
		}
	}
}
func (engine *Engine) Live() []Story {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	result := make([]Story, 0, len(engine.sessions))
	for _, item := range engine.sessions {
		result = append(result, clone(item.story))
	}
	sort.Slice(result, func(left, right int) bool { return result[left].LastSeen.After(result[right].LastSeen) })
	if len(result) > 100 {
		return result[:100]
	}
	return result
}
func (engine *Engine) Block(ip string, duration time.Duration) {
	engine.mu.Lock()
	until := engine.now().Add(duration)
	engine.blocks[ip] = until
	engine.mu.Unlock()
	engine.persistBlock(ip, until, "manual-or-high")
}

type blockWriter interface {
	SaveBlock(string, time.Time, string) error
}

func (engine *Engine) persistBlock(ip string, until time.Time, reason string) {
	if writer, ok := engine.writer.(blockWriter); ok {
		if err := writer.SaveBlock(ip, until, reason); err != nil {
			slog.Error("persist block state", "error", err)
		}
	}
}
func (engine *Engine) IsBlocked(ip string) bool {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.now().Before(engine.blocks[ip])
}
func (engine *Engine) Verdict(ip, userAgent, ja3 string) string {
	key := sha256.Sum256([]byte(ip + "\x00" + userAgent + "\x00" + ja3))
	identity := hex.EncodeToString(key[:12])
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if item := engine.sessions[identity]; item != nil && engine.now().Sub(item.touched) <= engine.window {
		return item.story.Verdict
	}
	return ""
}
func (engine *Engine) Close() {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	for _, item := range engine.sessions {
		engine.persist(item.story)
	}
}
