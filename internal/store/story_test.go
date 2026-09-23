package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mohdsaad0786/EpiLog/internal/story"
)

func TestSQLite(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "stories.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	until := time.Now().Add(24 * time.Hour)
	if err := store.SaveBlock("203.0.113.7", until, "critical"); err != nil {
		t.Fatal(err)
	}
	blocks, err := store.ActiveBlocks(context.Background(), time.Now())
	if err != nil || len(blocks) != 1 {
		t.Fatalf("vault block missing: %v / %v", blocks, err)
	}
	item := story.Story{ID: "unit-01", AttackerIP: "203.0.113.1", LastSeen: time.Now().UTC(), Verdict: "critical", ThreatScore: 94, Timeline: []story.TimelineEvent{{Method: "GET", Path: "/admin"}}}
	if err := store.Save(item); err != nil {
		t.Fatal(err)
	}
	result, err := store.Get(context.Background(), item.ID)
	if err != nil || result.ThreatScore != 94 {
		t.Fatalf("unexpected story: %+v / %v", result, err)
	}
	if err := store.MarkFalsePositive(context.Background(), item.ID); err != nil {
		t.Fatal(err)
	}
	result, err = store.Get(context.Background(), item.ID)
	if err != nil || !result.FalsePositive {
		t.Fatalf("false-positive flag missing: %+v / %v", result, err)
	}
	listed, err := store.List(context.Background(), "203.0.113.1", "critical", "", 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list result %+v / %v", listed, err)
	}
	if err := store.Prune(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	listed, err = store.List(context.Background(), "", "", "", 10)
	if err != nil || len(listed) != 0 {
		t.Fatalf("prune failed: %v / %v", listed, err)
	}
}
