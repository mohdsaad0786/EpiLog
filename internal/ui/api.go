package ui

import (
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mohdsaad0786/EpiLog/internal/events"
	"github.com/mohdsaad0786/EpiLog/internal/rules"
	"github.com/mohdsaad0786/EpiLog/internal/store"
	"github.com/mohdsaad0786/EpiLog/internal/story"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed static/*
var static embed.FS

type API struct {
	stories     *story.Engine
	store       store.StoryStore
	rules       *rules.Engine
	bus         events.Bus
	enabled     bool
	threatStats func() map[string]uint64
}

func New(stories *story.Engine, db store.StoryStore, engine *rules.Engine, bus events.Bus, enabled bool, registry *prometheus.Registry, threatStats func() map[string]uint64) http.Handler {
	api := &API{stories, db, engine, bus, enabled, threatStats}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/api/stories/live", api.live)
	mux.HandleFunc("/api/stories/", api.story)
	mux.HandleFunc("/api/stories", api.list)
	mux.HandleFunc("/api/attackers/top", api.attackers)
	mux.HandleFunc("/api/phases/stats", api.phases)
	mux.HandleFunc("/api/threats/stats", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != "GET" {
			http.Error(writer, "method not allowed", 405)
			return
		}
		respond(writer, api.threatStats())
	})
	mux.HandleFunc("/api/rules/", api.rule)
	mux.HandleFunc("/api/rules", api.listRules)
	content, _ := fs.Sub(static, "static")
	mux.Handle("/", http.FileServer(http.FS(content)))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; style-src 'self'; script-src 'self'; img-src 'self' data:")
		mux.ServeHTTP(writer, request)
	})
}
func respond(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}
func (api *API) combined(request *http.Request) ([]story.Story, error) {
	persisted, err := api.store.List(request.Context(), request.URL.Query().Get("ip"), request.URL.Query().Get("verdict"), request.URL.Query().Get("since"), 200)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	annotations := make(map[string]bool)
	for _, item := range persisted {
		annotations[item.ID] = item.FalsePositive
	}
	all := make([]story.Story, 0, len(persisted)+100)
	if api.enabled {
		for _, item := range api.stories.Live() {
			if ip := request.URL.Query().Get("ip"); ip != "" && ip != item.AttackerIP {
				continue
			}
			if verdict := request.URL.Query().Get("verdict"); verdict != "" && verdict != item.Verdict {
				continue
			}
			if since := request.URL.Query().Get("since"); since != "" && item.LastSeen.UTC().Format(time.RFC3339Nano) < since {
				continue
			}
			seen[item.ID] = true
			item.FalsePositive = annotations[item.ID]
			all = append(all, item)
		}
	}
	for _, item := range persisted {
		if !seen[item.ID] {
			all = append(all, item)
		}
	}
	sort.Slice(all, func(left, right int) bool { return all[left].LastSeen.After(all[right].LastSeen) })
	if len(all) > 200 {
		all = all[:200]
	}
	return all, nil
}
func (api *API) list(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(writer, "method not allowed", 405)
		return
	}
	items, err := api.combined(request)
	if err != nil {
		http.Error(writer, "database unavailable", 500)
		return
	}
	respond(writer, items)
}
func (api *API) story(writer http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/api/stories/")
	parts := strings.Split(path, "/")
	if parts[0] == "" || strings.Contains(parts[0], "/") {
		http.NotFound(writer, request)
		return
	}
	if len(parts) == 2 && parts[1] == "block" && request.Method == "POST" {
		if !api.enabled {
			http.Error(writer, "story correlation disabled", 403)
			return
		}
		if !api.validMutation(request) {
			http.Error(writer, "forbidden", 403)
			return
		}
		item, err := api.find(request, parts[0])
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		api.stories.Block(item.AttackerIP, 24*time.Hour)
		respond(writer, map[string]string{"status": "blocked"})
		return
	}
	if len(parts) == 2 && parts[1] == "false-positive" && request.Method == "POST" {
		if !api.validMutation(request) {
			http.Error(writer, "forbidden", 403)
			return
		}
		item, err := api.find(request, parts[0])
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		if err := api.store.Save(item); err != nil {
			http.Error(writer, "database unavailable", 500)
			return
		}
		if err := api.store.MarkFalsePositive(request.Context(), parts[0]); err != nil {
			http.Error(writer, "database unavailable", 500)
			return
		}
		respond(writer, map[string]string{"status": "marked"})
		return
	}
	if len(parts) != 1 || request.Method != "GET" {
		http.NotFound(writer, request)
		return
	}
	item, err := api.find(request, parts[0])
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(writer, request)
		} else {
			http.Error(writer, "database unavailable", 500)
		}
		return
	}
	respond(writer, item)
}
func (api *API) find(request *http.Request, id string) (story.Story, error) {
	item, err := api.store.Get(request.Context(), id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return item, err
	}
	if api.enabled {
		for _, live := range api.stories.Live() {
			if live.ID == id {
				live.FalsePositive = item.FalsePositive
				return live, nil
			}
		}
	}
	if err == nil {
		return item, nil
	}
	return story.Story{}, sql.ErrNoRows
}
func (api *API) validMutation(request *http.Request) bool {
	if origin := request.Header.Get("Origin"); origin != "" && origin != "http://"+request.Host && origin != "https://"+request.Host {
		return false
	}
	return request.Header.Get("Content-Type") == "application/json"
}
func (api *API) live(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(writer, "method not allowed", 405)
		return
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(request *http.Request) bool {
		return request.Header.Get("Origin") == "http://"+request.Host || request.Header.Get("Origin") == "https://"+request.Host
	}}
	connection, err := upgrader.Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	channel, cancel := api.bus.Subscribe()
	defer cancel()
	if api.enabled {
		if err := connection.WriteJSON(events.Event{Topic: "initial", Data: api.stories.Live()}); err != nil {
			return
		}
	}
	for {
		select {
		case <-request.Context().Done():
			return
		case event, open := <-channel:
			if !open || connection.WriteJSON(event) != nil {
				return
			}
		}
	}
}
func (api *API) attackers(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(writer, "method not allowed", 405)
		return
	}
	items, err := api.combined(request)
	if err != nil {
		http.Error(writer, "database unavailable", 500)
		return
	}
	type total struct {
		IP       string `json:"ip"`
		Requests int    `json:"requests"`
		Score    int    `json:"score"`
	}
	summary := map[string]*total{}
	for _, item := range items {
		entry := summary[item.AttackerIP]
		if entry == nil {
			entry = &total{IP: item.AttackerIP}
			summary[item.AttackerIP] = entry
		}
		entry.Requests += item.TotalRequests
		if item.ThreatScore > entry.Score {
			entry.Score = item.ThreatScore
		}
	}
	result := make([]total, 0, len(summary))
	for _, entry := range summary {
		result = append(result, *entry)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Score > result[right].Score })
	if len(result) > 20 {
		result = result[:20]
	}
	respond(writer, result)
}
func (api *API) phases(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(writer, "method not allowed", 405)
		return
	}
	items, err := api.combined(request)
	if err != nil {
		http.Error(writer, "database unavailable", 500)
		return
	}
	result := map[story.Phase]int{}
	for _, item := range items {
		for _, phase := range item.Phases {
			result[phase]++
		}
	}
	respond(writer, result)
}
func (api *API) listRules(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(writer, "method not allowed", 405)
		return
	}
	respond(writer, api.rules.List())
}
func (api *API) rule(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" || !api.validMutation(request) {
		http.Error(writer, "forbidden", 403)
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/api/rules/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(writer, request)
		return
	}
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(request.Body, 128)).Decode(&payload); err != nil {
		http.Error(writer, "invalid JSON", 400)
		return
	}
	if !api.rules.SetEnabled(id, payload.Enabled) {
		http.NotFound(writer, request)
		return
	}
	respond(writer, map[string]bool{"enabled": payload.Enabled})
}
