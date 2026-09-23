package rules

import "strings"

type node struct {
	children map[byte]int
	fallback int
	outputs  []int
}
type automaton struct{ nodes []node }

func (matcher *automaton) add(pattern string, index int) {
	state := 0
	for position := 0; position < len(pattern); position++ {
		letter := pattern[position]
		next, ok := matcher.nodes[state].children[letter]
		if !ok {
			next = len(matcher.nodes)
			matcher.nodes[state].children[letter] = next
			matcher.nodes = append(matcher.nodes, node{children: make(map[byte]int)})
		}
		state = next
	}
	matcher.nodes[state].outputs = append(matcher.nodes[state].outputs, index)
}
func (matcher *automaton) compile() {
	queue := make([]int, 0)
	for _, child := range matcher.nodes[0].children {
		queue = append(queue, child)
	}
	for position := 0; position < len(queue); position++ {
		state := queue[position]
		for letter, child := range matcher.nodes[state].children {
			parent := matcher.nodes[state].fallback
			for parent != 0 {
				if _, ok := matcher.nodes[parent].children[letter]; ok {
					break
				}
				parent = matcher.nodes[parent].fallback
			}
			if next, ok := matcher.nodes[parent].children[letter]; ok {
				matcher.nodes[child].fallback = next
			}
			matcher.nodes[child].outputs = append(matcher.nodes[child].outputs, matcher.nodes[matcher.nodes[child].fallback].outputs...)
			queue = append(queue, child)
		}
	}
}
func (matcher *automaton) find(value string) int {
	best := -1
	state := 0
	value = strings.ToLower(value)
	for position := 0; position < len(value); position++ {
		letter := value[position]
		for state != 0 {
			if _, ok := matcher.nodes[state].children[letter]; ok {
				break
			}
			state = matcher.nodes[state].fallback
		}
		if next, ok := matcher.nodes[state].children[letter]; ok {
			state = next
		}
		for _, index := range matcher.nodes[state].outputs {
			if best < 0 || index < best {
				best = index
			}
		}
	}
	return best
}
func buildLiterals(items []compiled) map[string]*automaton {
	result := make(map[string]*automaton)
	for index, rule := range items {
		if rule.Literal == "" {
			continue
		}
		for _, target := range rule.Targets {
			matcher := result[target]
			if matcher == nil {
				matcher = &automaton{nodes: []node{{children: make(map[byte]int)}}}
				result[target] = matcher
			}
			matcher.add(strings.ToLower(rule.Literal), index)
		}
	}
	for _, matcher := range result {
		matcher.compile()
	}
	return result
}
func (current *snapshot) literalMatch(input Input) int {
	best := -1
	values := map[string]string{"path": input.Path, "query": input.Query, "body": input.Body, "headers": input.Headers, "user_agent": input.UserAgent}
	for target, matcher := range current.literals {
		if value := values[target]; value != "" {
			index := matcher.find(value)
			if index >= 0 && (best < 0 || index < best) {
				best = index
			}
		}
	}
	return best
}
