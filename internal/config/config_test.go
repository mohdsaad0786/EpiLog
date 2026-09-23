package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("story:\n  window: 3m\n  retention: 48h\n"), 0600); err != nil {
		t.Fatal(err)
	}
	settings, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Story.Window != 3*time.Minute || settings.Story.Retention != 48*time.Hour {
		t.Fatalf("unexpected durations: %+v", settings.Story)
	}
}
