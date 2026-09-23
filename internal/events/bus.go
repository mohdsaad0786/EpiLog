package events

import "sync"

type Event struct {
	Topic string `json:"topic"`
	Data  any    `json:"data"`
}
type Bus interface {
	Publish(Event)
	Subscribe() (<-chan Event, func())
}
type Memory struct {
	mu        sync.RWMutex
	next      int
	listeners map[int]chan Event
}

func NewMemory() *Memory { return &Memory{listeners: make(map[int]chan Event)} }
func (bus *Memory) Publish(event Event) {
	bus.mu.RLock()
	defer bus.mu.RUnlock()
	for _, listener := range bus.listeners {
		select {
		case listener <- event:
		default:
		}
	}
}
func (bus *Memory) Subscribe() (<-chan Event, func()) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	bus.next++
	key := bus.next
	channel := make(chan Event, 64)
	bus.listeners[key] = channel
	var once sync.Once
	return channel, func() { once.Do(func() { bus.mu.Lock(); delete(bus.listeners, key); close(channel); bus.mu.Unlock() }) }
}
