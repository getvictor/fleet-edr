package main

import "testing"

func TestIsExcluded(t *testing.T) {
	cases := map[string]bool{
		"tools/dash-lint/main.go":            true,
		"tools/dash-lint/main_test.go":       true,
		".claude/commands/x.md":              true,
		"openspec/changes/archive/a.md":      true,
		"docs/maintenance/log.md":            true,
		"docs/okta-setup.md":                 false,
		"server/rules/internal/catalog/x.go": false,
		"tools/spectrace/README.md":          false,
	}
	for path, want := range cases {
		if got := isExcluded(path); got != want {
			t.Errorf("isExcluded(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestCheckMarkdown(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"prose em dash", "The tenant - Okta - rejects it.\n", 1},
		{"list marker not flagged", "- first item\n  - nested item\n", 0},
		{"list item with internal em dash flagged", "- term - definition\n", 1},
		{"table separator not flagged", "| a | b |\n| --- | --- |\n", 0},
		{"table cell em dash flagged", "| state - mismatch | cookie |\n", 1},
		{"fenced code skipped", "```sh\nfor i in 1 - 2\n```\n", 0},
		{"inline code span skipped", "Run `cpu - 2` to compute.\n", 0},
		{"compound word not flagged", "per-IP rate limit and bounded-context split\n", 0},
		{"double hyphen not flagged", "pass the --flag -- it works\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(checkMarkdown("x.md", []byte(tc.in))); got != tc.want {
				t.Fatalf("checkMarkdown(%q) = %d findings, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckGo(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"arithmetic not flagged", "package p\nfunc f(n int) int { return n - 1 }\n", 0},
		{"line comment flagged", "package p\n// the gate - and its backstop - both fire\nvar x = 1\n", 1},
		{"doc string flagged", "package p\nvar d = \"isolates the host - irreversible\"\n", 1},
		{"clean code and comment", "package p\n// computes n minus one\nfunc f(n int) int { return n - 1 }\n", 0},
		{"raw string flagged", "package p\nvar d = `step one - then two`\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(checkGo("x.go", []byte(tc.in))); got != tc.want {
				t.Fatalf("checkGo(%q) = %d findings, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckCStyleComments(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"swift arithmetic not flagged", "let x = count - 1\n", 0},
		{"line comment flagged", "let x = 1 // count - 1 here\n", 1},
		{"url in code not flagged", "let u = \"https://example.com/a-b\"\n", 0},
		{"block comment flagged", "/* the rule - high severity - fires */\nlet y = 2\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(checkCStyleComments("x.swift", []byte(tc.in))); got != tc.want {
				t.Fatalf("checkCStyleComments(%q) = %d findings, want %d", tc.in, got, tc.want)
			}
		})
	}
}
