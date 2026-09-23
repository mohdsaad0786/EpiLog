package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
	rate    float64
	burst   float64
}

func New(rate float64, burst int) *Limiter {
	return &Limiter{buckets: make(map[string]bucket), rate: rate, burst: float64(burst)}
}
func (limiter *Limiter) Allow(key string) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := time.Now()
	entry, exists := limiter.buckets[key]
	if !exists {
		entry = bucket{limiter.burst, now}
	}
	entry.tokens += now.Sub(entry.last).Seconds() * limiter.rate
	if entry.tokens > limiter.burst {
		entry.tokens = limiter.burst
	}
	entry.last = now
	allowed := entry.tokens >= 1
	if allowed {
		entry.tokens--
	}
	limiter.buckets[key] = entry
	return allowed
}
func (limiter *Limiter) Sweep() {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := time.Now()
	for key, entry := range limiter.buckets {
		if now.Sub(entry.last) > time.Duration(limiter.burst/limiter.rate)*time.Second+time.Minute {
			delete(limiter.buckets, key)
		}
	}
}
