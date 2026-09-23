package story

func score(story Story, torVPN bool) (int, string) {
	base := 0
	for _, match := range story.RuleMatches {
		switch match.Severity {
		case "critical":
			if base < 90 {
				base = 90
			}
		case "high":
			if base < 60 {
				base = 60
			}
		case "medium":
			if base < 30 {
				base = 30
			}
		case "low":
			if base < 10 {
				base = 10
			}
		}
	}
	bonus := story.BlockedRequests * 5
	if bonus > 30 {
		bonus = 30
	}
	value := base + bonus
	if len(story.Phases) > 1 {
		value += 20
	}
	if torVPN {
		value += 15
	}
	recon, attack := false, false
	for _, event := range story.Timeline {
		if event.Phase == Recon {
			recon = true
		}
		if recon && (event.Phase == Injection || event.Phase == BruteForce) {
			attack = true
		}
	}
	if attack {
		value += 10
	}
	if value > 100 {
		value = 100
	}
	switch {
	case value > 85:
		return value, "critical"
	case value > 60:
		return value, "high"
	case value > 30:
		return value, "medium"
	default:
		return value, "low"
	}
}
