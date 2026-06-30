package main

import "testing"

func TestIsExcluded(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"tools/dash-lint/main.go":                  true,
		"tools/dash-lint/main_test.go":             true,
		".claude/commands/x.md":                    true,
		"openspec/changes/archive/a.md":            true,
		"server/apidocs/embed/redoc.standalone.js": true,
		"docs/maintenance/log.md":                  true,
		"docs/okta-setup.md":                       false,
		"server/rules/internal/catalog/x.go":       false,
		"tools/spectrace/README.md":                false,
	}
	for path, want := range cases {
		if got := isExcluded(path); got != want {
			t.Errorf("isExcluded(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestCheckMarkdown(t *testing.T) {
	t.Parallel()
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
		{"indented code block skipped", "Run it:\n\n    task uat:l5 -- attack-runbook\n    task uat:l5 -- app-control-block\n", 0},
		{"prose after indented block still scanned", "Run it:\n\n    task uat:l5 -- x\n\nthe result -- a pass -- is shown\n", 1},
		{"inline code span skipped", "Run `cpu - 2` to compute.\n", 0},
		{"compound word not flagged", "per-IP rate limit and bounded-context split\n", 0},
		{"flag-only line not flagged", "pass the --flag to enable it\n", 0},
		{"double-hyphen em dash flagged", "the tenant -- Okta -- rejects it\n", 1},
		{"horizontal rule not flagged", "a --- b is a rule, not an em dash\n", 0},
		{"ignore directive skips line", "the tenant -- Okta -- rejects it dash-lint:ignore\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(checkMarkdown("x.md", []byte(tc.in))); got != tc.want {
				t.Fatalf("checkMarkdown(%q) = %d findings, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckGo(t *testing.T) {
	t.Parallel()
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
		{"escaped newline not flagged", "package p\nvar d = \"\\n - some list item\"\n", 0},
		{"double-hyphen comment flagged", "package p\n// the order -- rotate then ack -- matters\nvar x = 1\n", 1},
		{"backtick code span in comment not flagged", "package p\n// run `git diff -- file` to inspect\nvar x = 1\n", 0},
		{"gosec justification separator not flagged", "package p\n// #nosec G101 -- test fixture: not a real credential\nvar x = 1\n", 0},
		{"prose after gosec separator still flagged", "package p\n// #nosec G101 -- a token -- not real\nvar x = 1\n", 1},
		{"ignore directive skips line", "package p\n// the order -- rotate then ack dash-lint:ignore\nvar x = 1\n", 0},
		// Block-comment directive granularity: the ignore directive on a later line of a /* */ block suppresses only that
		// line; a violation on a different line of the same block is still reported (at its own line).
		{"block comment ignore is per-line", "package p\n/*\n the order -- rotate then ack dash-lint:ignore\n*/\nvar x = 1\n", 0},
		{"block comment reports per-line", "package p\n/* clean opener\n the order -- rotate then ack\n*/\nvar x = 1\n", 1},
		{"block comment violation despite directive on other line", "package p\n/* the order -- rotate dash-lint:ignore\n the ack -- second\n*/\nvar x = 1\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(checkGo("x.go", []byte(tc.in))); got != tc.want {
				t.Fatalf("checkGo(%q) = %d findings, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckCStyleComments(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"swift arithmetic not flagged", "let x = count - 1\n", 0},
		{"line comment flagged", "let x = 1 // count - 1 here\n", 1},
		{"url in code not flagged", "let u = \"https://example.com/a-b\"\n", 0},
		{"block comment flagged", "/* the rule - high severity - fires */\nlet y = 2\n", 1},
		{"multi-line block comment flagged", "/*\n the rule - high severity - fires\n*/\nlet y = 2\n", 1},
		{"multi-line block comment clean", "/*\n computes count minus one\n*/\nlet y = count - 1\n", 0},
		{"double-hyphen line comment flagged", "let x = 1 // the order -- rotate then ack -- matters\n", 1},
		{"backtick code span not flagged", "let x = 1 // run `task uat:l5 -- attack-runbook` to start\n", 0},
		{"eslint-disable description separator not flagged",
			"// eslint-disable-next-line react-hooks/set-state-in-effect -- intentional reset on prop change\nlet z = 3\n", 0},
		{"prose after eslint separator still flagged",
			"// eslint-disable-next-line foo/bar -- the reset -- which is intentional\nlet z = 3\n", 1},
		{"ignore directive skips line", "let x = 1 // the order -- rotate then ack dash-lint:ignore\n", 0},
		// Regression: a "/*" inside a // line comment (here a "/*.json" glob) must not be read as a block-comment open and
		// swallow the rest of the file. With the bug, line 2's "count - 1" code was scanned as comment text and flagged.
		{"slash-star inside line comment not a block open", "// the glob is /*.json here\nlet x = count - 1\n", 0},
		{"em dash in line comment with slash-star still flagged", "// glob /*.json maps - to dashes\nlet x = 1\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(checkCStyleComments("x.swift", []byte(tc.in))); got != tc.want {
				t.Fatalf("checkCStyleComments(%q) = %d findings, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckFile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		path string
		in   string
		want int
	}{
		{"markdown dispatch", "x.md", "the tenant - Okta - rejects it\n", 1},
		{"go dispatch", "x.go", "package p\n// the order -- and the ack -- matter\n", 1},
		{"swift dispatch", "x.swift", "let x = 1 // count - 1 here\n", 1},
		{"yaml dispatch", "x.yaml", "k: v # the tenant - Okta - here\n", 1},
		{"shell dispatch", "x.sh", "# the tenant - Okta - here\n", 1},
		{"unknown extension ignored", "x.txt", "the tenant - Okta - rejects it\n", 0},
		// Machine-generated source is skipped: the standard generated marker suppresses the whole file, so a tool-emitted
		// version list (e.g. protoc-gen-go's "// - protoc v7.34.1") is not flagged.
		{"generated go file skipped", "x.pb.go", "// Code generated by protoc-gen-go. DO NOT EDIT.\n// - protoc v7.34.1\npackage p\n", 0},
		{"non-generated go with similar comment still flagged", "x.go", "package p\n// generated - but not by the marker\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(checkFile(tc.path, []byte(tc.in))); got != tc.want {
				t.Fatalf("checkFile(%q, %q) = %d findings, want %d", tc.path, tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckHashComments(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"yaml comment single hyphen flagged", "key: value # the tenant - Okta - rejects it\n", 1},
		{"yaml comment double hyphen flagged", "key: value # the order -- rotate then ack -- matters\n", 1},
		{"shell full-line comment flagged", "# explicitly NOT malicious - every step is benign\necho hi\n", 1},
		{"yaml flow value not flagged", "args: [a, -, b]\nrange: 1 - 2\n", 0},
		{"shell arithmetic not flagged", "x=$((count - 1))\n", 0},
		{"variable expansion ignored, trailing comment scanned", "n=${#array[@]} # count - here\n", 1},
		{"backtick code span in comment not flagged", "# run `task uat:l5 -- attack-runbook` to start\necho hi\n", 0},
		{"list-like comment marker not flagged", "#   - first bullet item in a comment\n", 0},
		{"ignore directive skips line", "key: value # the order -- rotate dash-lint:ignore\n", 0},
		// Quote-awareness: a '#' inside a quoted scalar/string is not a comment, so its content must not be scanned.
		{"hash inside double-quoted scalar not a comment", "key: \"a # b - c\"\n", 0},
		{"hash inside single-quoted scalar not a comment", "cmd: 'echo # x - y'\n", 0},
		{"real comment after quoted scalar still scanned", "key: \"a # b\" # real - comment\n", 1},
		{"em dash inside a quoted segment of a real comment flagged", "key: v # note \"x - y\" here\n", 1},
		{"escaped quote keeps double-quote region open", "key: \"a \\\" # b - c\"\n", 0},
		{"doubled single-quote escape stays quoted", "key: 'a '' # b - c'\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(checkHashComments("x.yml", []byte(tc.in))); got != tc.want {
				t.Fatalf("checkHashComments(%q) = %d findings, want %d", tc.in, got, tc.want)
			}
		})
	}
}
