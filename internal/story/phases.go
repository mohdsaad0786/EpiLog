package story

import (
	"strings"
	"time"
)

func detectPhases(timeline []TimelineEvent, observation Observation) []Phase {
	var phases []Phase
	add := func(phase Phase) {
		for _, existing := range phases {
			if existing == phase {
				return
			}
		}
		phases = append(phases, phase)
	}
	path := strings.ToLower(observation.Path)
	if observation.Status >= 400 && observation.Status < 500 || strings.Contains(path, "/admin") || strings.Contains(path, "/.env") || strings.Contains(path, "/wp-admin") {
		add(Recon)
	}
	notFound, loginPosts := 0, 0
	if observation.Status == 404 {
		notFound++
	}
	if observation.Method == "POST" && authPath(observation.Path) {
		loginPosts++
	}
	for _, event := range timeline {
		if observation.At.Sub(event.Timestamp) > 10*time.Minute {
			continue
		}
		if event.Status == 404 {
			notFound++
		}
		if event.Method == "POST" && authPath(event.Path) {
			loginPosts++
		}
	}
	if notFound >= 5 {
		add(Scan)
	}
	if loginPosts >= 3 {
		add(BruteForce)
	}
	switch observation.Category {
	case "sqli", "xss", "rce", "lfi", "ssrf", "xxe":
		add(Injection)
	}
	if observation.ResponseBytes > 1024*1024 && (strings.Contains(path, "export") || strings.Contains(path, "dump") || strings.Contains(path, "backup")) {
		add(Exfil)
	}
	if (observation.Method == "POST" || observation.Method == "PUT") && (strings.Contains(path, "upload") || strings.Contains(path, "/users")) {
		add(Persistence)
	}
	return phases
}

func authPath(path string) bool {
	path = strings.ToLower(path)
	return strings.Contains(path, "login") || strings.Contains(path, "/auth") || strings.Contains(path, "/api/token")
}
