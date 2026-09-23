package threat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReputation(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.Write([]byte("203.0.113.13\n")) }))
	defer feed.Close()
	reputation, err := New(feed.URL, []string{"198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reputation.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reputation.Lookup("203.0.113.13") != "tor" || reputation.Lookup("198.51.100.5") != "vpn" || reputation.Lookup("8.8.8.8") != "" {
		t.Fatal("unexpected reputation classification")
	}
}
