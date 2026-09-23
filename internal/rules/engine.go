package rules

import (
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
)

type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Category    string   `yaml:"category" json:"category"`
	Severity    string   `yaml:"severity" json:"severity"`
	Description string   `yaml:"description" json:"description"`
	Pattern     string   `yaml:"pattern" json:"pattern"`
	Literal     string   `yaml:"literal,omitempty" json:"literal,omitempty"`
	Targets     []string `yaml:"targets" json:"targets"`
	Action      string   `yaml:"action" json:"action"`
	Tags        []string `yaml:"tags" json:"tags"`
	Enabled     bool     `yaml:"-" json:"enabled"`
}

type Match struct {
	Matched  bool   `json:"matched"`
	RuleID   string `json:"rule_id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
}
type Input struct{ Path, Query, Body, Headers, UserAgent string }
type compiled struct {
	Rule
	regex *regexp.Regexp
}
type snapshot struct {
	rules    []compiled
	visible  []Rule
	literals map[string]*automaton
}
type Engine struct {
	current  atomic.Pointer[snapshot]
	mu       sync.Mutex
	disabled map[string]bool
}

func NewEngine(items []Rule) (*Engine, error) {
	engine := &Engine{disabled: make(map[string]bool)}
	if err := engine.Replace(items); err != nil {
		return nil, err
	}
	return engine, nil
}

func (engine *Engine) Replace(items []Rule) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	result := &snapshot{visible: append([]Rule(nil), items...)}
	for _, rule := range items {
		for index := range result.visible {
			if result.visible[index].ID == rule.ID {
				result.visible[index].Enabled = !engine.disabled[rule.ID]
				break
			}
		}
		if engine.disabled[rule.ID] {
			continue
		}
		compiledRule := compiled{Rule: rule}
		if rule.Literal == "" {
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return err
			}
			compiledRule.regex = regex
		}
		result.rules = append(result.rules, compiledRule)
	}
	sort.SliceStable(result.rules, func(left, right int) bool {
		return priority(result.rules[left].Severity) > priority(result.rules[right].Severity)
	})
	result.literals = buildLiterals(result.rules)
	engine.current.Store(result)
	return nil
}

func priority(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func (engine *Engine) Evaluate(input Input) Match {
	current := engine.current.Load()
	literalIndex := current.literalMatch(input)
	for index, rule := range current.rules {
		if literalIndex >= 0 && index > literalIndex {
			break
		}
		if rule.Literal != "" {
			continue
		}
		for _, target := range rule.Targets {
			var value string
			switch target {
			case "path":
				value = input.Path
			case "query":
				value = input.Query
			case "body":
				value = input.Body
			case "headers":
				value = input.Headers
			case "user_agent":
				value = input.UserAgent
			}
			if value != "" && rule.regex.MatchString(value) {
				return Match{true, rule.ID, rule.Category, rule.Severity, rule.Action}
			}
		}
	}
	if literalIndex >= 0 {
		rule := current.rules[literalIndex]
		return Match{true, rule.ID, rule.Category, rule.Severity, rule.Action}
	}
	return Match{}
}

func (engine *Engine) List() []Rule { return append([]Rule(nil), engine.current.Load().visible...) }

func (engine *Engine) SetEnabled(id string, enabled bool) bool {
	engine.mu.Lock()
	items := engine.current.Load().visible
	found := false
	for _, rule := range items {
		if rule.ID == id {
			found = true
			break
		}
	}
	if found {
		engine.disabled[id] = !enabled
	}
	engine.mu.Unlock()
	if found {
		_ = engine.Replace(items)
	}
	return found
}
