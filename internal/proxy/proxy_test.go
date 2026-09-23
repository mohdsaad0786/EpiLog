package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mohdsaad0786/EpiLog/internal/challenge"
	"github.com/mohdsaad0786/EpiLog/internal/events"
	"github.com/mohdsaad0786/EpiLog/internal/ratelimit"
	"github.com/mohdsaad0786/EpiLog/internal/rules"
	"github.com/mohdsaad0786/EpiLog/internal/story"
	"github.com/mohdsaad0786/EpiLog/internal/threat"
	"github.com/prometheus/client_golang/prometheus"
)

func TestProxyPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.Write([]byte("upstream ok")) }))
	defer upstream.Close()
	items, err := rules.Load("")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.NewEngine(items)
	if err != nil {
		t.Fatal(err)
	}
	stories := story.NewEngine(nil, events.NewMemory(), 5*time.Minute, 86, 24*time.Hour)
	reputation, err := threat.New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	pow, err := challenge.New("abcdefghijklmnop1234567890", 2)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(upstream.URL, engine, stories, ratelimit.New(100, 50), reputation, pow, 1024, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service)
	defer server.Close()
	response, err := http.Post(server.URL+"/upload", "text/plain", strings.NewReader(strings.Repeat("x", 1025)))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 413 {
		t.Errorf("expected oversized request rejection, got %d", response.StatusCode)
	}
	for _, test := range []struct {
		path   string
		status int
	}{{"/safe", 200}, {"/?id=1%20UNION%20SELECT%20password%20FROM%20users", 403}, {"/../../etc/passwd", 403}} {
		response, err := http.Get(server.URL + test.path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != test.status {
			t.Errorf("%s: expected %d, got %d", test.path, test.status, response.StatusCode)
		}
	}
}
