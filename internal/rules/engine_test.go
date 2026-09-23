package rules

import (
	"testing"
)

func TestCatalog(t *testing.T) {
	items, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 500 {
		t.Fatalf("catalog contains %d rules", len(items))
	}
	engine, err := NewEngine(items)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		input    Input
		category string
	}{{Input{Query: "id=1 UNION SELECT password FROM users"}, "sqli"}, {Input{Body: "<script>alert(1)</script>"}, "xss"}, {Input{Path: "/../../etc/passwd"}, "lfi"}, {Input{Body: "<!DOCTYPE x [<!ENTITY foo SYSTEM 'file:///etc/passwd'>]>"}, "xxe"}}
	for _, test := range cases {
		match := engine.Evaluate(test.input)
		if match.Category != test.category {
			t.Errorf("input %+v: got %+v, want %s", test.input, match, test.category)
		}
	}
}
func TestToggle(t *testing.T) {
	engine, err := NewEngine([]Rule{{ID: "custom-001", Category: "custom", Severity: "high", Literal: "secret", Targets: []string{"path"}, Action: "block"}})
	if err != nil {
		t.Fatal(err)
	}
	if !engine.Evaluate(Input{Path: "/secret"}).Matched {
		t.Fatal("expected match")
	}
	if !engine.SetEnabled("custom-001", false) {
		t.Fatal("missing rule")
	}
	if engine.Evaluate(Input{Path: "/secret"}).Matched {
		t.Fatal("disabled rule matched")
	}
}
func BenchmarkEvaluate(b *testing.B) {
	items, err := Load("")
	if err != nil {
		b.Fatal(err)
	}
	engine, err := NewEngine(items)
	if err != nil {
		b.Fatal(err)
	}
	input := Input{Path: "/products", Query: "page=2&sort=asc", Headers: "Accept:application/json", UserAgent: "Mozilla/5.0"}
	b.ResetTimer()
	for range b.N {
		_ = engine.Evaluate(input)
	}
}
