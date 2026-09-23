package rules

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

//go:embed categories/*.yaml
var builtin embed.FS

var categoryCounts = map[string]int{"sqli": 100, "xss": 80, "rce": 60, "lfi": 50, "ssrf": 40, "xxe": 30, "scanner": 60, "bot": 40, "custom": 40}

func Load(dir string) ([]Rule, error) {
	var files fs.FS = builtin
	root := "categories"
	if dir != "" {
		files = os.DirFS(dir)
		root = "."
	}
	entries, err := fs.ReadDir(files, root)
	if err != nil {
		return nil, err
	}
	var result []Rule
	seen := make(map[string]bool)
	counts := make(map[string]int)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := fs.ReadFile(files, filepath.ToSlash(filepath.Join(root, entry.Name())))
		if err != nil {
			return nil, err
		}
		var group []Rule
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&group); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		for _, rule := range group {
			if seen[rule.ID] || rule.ID == "" || categoryCounts[rule.Category] == 0 || !strings.HasPrefix(rule.ID, rule.Category+"-") || (rule.Pattern == "") == (rule.Literal == "") || len(rule.Targets) == 0 {
				return nil, fmt.Errorf("invalid/duplicate rule %q", rule.ID)
			}
			if priority(rule.Severity) == 1 && rule.Severity != "low" {
				return nil, fmt.Errorf("invalid severity in %s", rule.ID)
			}
			if rule.Action != "block" && rule.Action != "challenge" && rule.Action != "log" {
				return nil, fmt.Errorf("invalid action in %s", rule.ID)
			}
			for _, target := range rule.Targets {
				switch target {
				case "path", "query", "body", "headers", "user_agent":
				default:
					return nil, fmt.Errorf("invalid target in %s", rule.ID)
				}
			}
			seen[rule.ID] = true
			counts[rule.Category]++
			result = append(result, rule)
		}
	}
	for category, count := range categoryCounts {
		if counts[category] != count {
			return nil, fmt.Errorf("%s: expected %d rules, got %d", category, count, counts[category])
		}
	}
	return result, nil
}

func Watch(dir string, engine *Engine, onError func(error)) (func(), error) {
	if dir == "" {
		return func() {}, nil
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer watcher.Close()
		for {
			select {
			case <-done:
				return
			case _, ok := <-watcher.Events:
				if !ok {
					return
				}
				items, err := Load(dir)
				if err == nil {
					err = engine.Replace(items)
				}
				if err != nil {
					onError(err)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				onError(err)
			}
		}
	}()
	return func() { close(done) }, nil
}
