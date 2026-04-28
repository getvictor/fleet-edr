// gen-rule-docs renders docs/detection-rules.md from the structured Documentation
// each rule exposes via detection.Rule.Doc(). Run via:
//
//	go run ./tools/gen-rule-docs
//
// Output is intentionally deterministic (registration order, no timestamps) so
// the generated file is diff-friendly and CI-checkable. A future CI step can
// re-run the generator and fail on drift.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/detection/rules"
)

// allRegisteredRules mirrors the registration list in
// server/cmd/fleet-edr-server/main.go. We intentionally instantiate with EMPTY
// allowlists here — the documentation is not a function of a particular
// deployment's tuning, it documents the shape of the knob.
//
// Order matches main.go so the generated markdown lists rules in the same
// order they fire at runtime.
func allRegisteredRules() []detection.Rule {
	return []detection.Rule{
		&rules.SuspiciousExec{},
		&rules.PersistenceLaunchAgent{},
		&rules.DyldInsert{},
		&rules.ShellFromOffice{},
		&rules.OsascriptNetworkExec{},
		&rules.CredentialKeychainDump{},
		&rules.PrivilegeLaunchdPlistWrite{},
		&rules.SudoersTamper{},
	}
}

func main() {
	out := flag.String("out", "docs/detection-rules.md", "destination markdown file")
	flag.Parse()

	if err := generate(*out); err != nil {
		log.Fatalf("%v", err)
	}
}

// generate is split out so the deferred close runs even on a render error.
// `main` calling log.Fatalf with a defer in scope leaves the file unclosed
// (gocritic exitAfterDefer); pulling the body up here makes the close happen
// before main exits.
func generate(out string) error {
	f, err := os.Create(out) //nolint:gosec // path is operator-controlled
	if err != nil {
		return fmt.Errorf("create %s: %w", out, err)
	}
	defer func() { _ = f.Close() }()
	if err := render(f, allRegisteredRules()); err != nil {
		return fmt.Errorf("render: %w", err)
	}
	return nil
}

// render writes the full document body to w. Split out from main so a test can
// drive it against a buffer and snapshot-compare against the committed file.
func render(w io.Writer, rs []detection.Rule) error {
	var b strings.Builder
	b.WriteString("# Detection rules\n\n")
	b.WriteString("This page is generated from `tools/gen-rule-docs` by walking the\n")
	b.WriteString("`detection.Rule.Doc()` method on every rule registered in\n")
	b.WriteString("`server/cmd/fleet-edr-server/main.go`. To refresh after changing a\n")
	b.WriteString("rule's documentation, run:\n\n")
	b.WriteString("```sh\n")
	b.WriteString("go run ./tools/gen-rule-docs\n")
	b.WriteString("```\n\n")
	b.WriteString("Hand-edits to this file get overwritten on the next regeneration.\n\n")

	// Index — operators jumping in from a CVE or alert title want a fast\n
	// lookup. ID is what shows up in alert rows; title is the friendly name.
	b.WriteString("## Index\n\n")
	b.WriteString("| Rule ID | Title | Severity | ATT&CK |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, r := range rs {
		d := r.Doc()
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s | %s | %s |\n",
			r.ID(), anchor(r.ID()), d.Title, d.Severity, strings.Join(r.Techniques(), ", "))
	}
	b.WriteString("\n")

	for _, r := range rs {
		writeRule(&b, r)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func writeRule(b *strings.Builder, r detection.Rule) {
	d := r.Doc()
	id := r.ID()

	fmt.Fprintf(b, "## %s\n\n", id)
	fmt.Fprintf(b, "**%s**  \n", d.Title)
	if d.Summary != "" {
		fmt.Fprintf(b, "%s\n\n", d.Summary)
	}

	b.WriteString("| | |\n| --- | --- |\n")
	fmt.Fprintf(b, "| Rule ID | `%s` |\n", id)
	fmt.Fprintf(b, "| Severity | `%s` |\n", d.Severity)
	if techs := r.Techniques(); len(techs) > 0 {
		fmt.Fprintf(b, "| ATT&CK | %s |\n", joinTechniqueLinks(techs))
	}
	if len(d.EventTypes) > 0 {
		fmt.Fprintf(b, "| Event types | %s |\n", joinCode(d.EventTypes))
	}
	b.WriteString("\n")

	if d.Description != "" {
		b.WriteString("### Description\n\n")
		b.WriteString(d.Description)
		b.WriteString("\n\n")
	}

	if len(d.Config) > 0 {
		b.WriteString("### Configuration\n\n")
		b.WriteString("| Env var | Type | Default | Description |\n")
		b.WriteString("| --- | --- | --- | --- |\n")
		for _, c := range d.Config {
			def := c.Default
			if def == "" {
				def = "_(unset)_"
			} else {
				def = "`" + def + "`"
			}
			fmt.Fprintf(b, "| `%s` | `%s` | %s | %s |\n", c.EnvVar, c.Type, def, c.Description)
		}
		b.WriteString("\n")
	}

	if len(d.FalsePositives) > 0 {
		b.WriteString("### Known false-positive sources\n\n")
		for _, fp := range d.FalsePositives {
			fmt.Fprintf(b, "- %s\n", fp)
		}
		b.WriteString("\n")
	}

	if len(d.Limitations) > 0 {
		b.WriteString("### Limitations\n\n")
		for _, l := range d.Limitations {
			fmt.Fprintf(b, "- %s\n", l)
		}
		b.WriteString("\n")
	}
}

// anchor produces the GitHub-flavoured-markdown anchor slug for a heading.
// Our heading is the bare rule ID, which is already lowercase + underscored
// + ASCII, so the slug is the ID verbatim. Centralised so a future ID with
// less-friendly characters has one place to fix.
func anchor(id string) string { return id }

// joinTechniqueLinks renders each technique ID as a link to its MITRE page.
// Sub-techniques (e.g. T1574.006) need the dot translated to a slash in the
// URL path: attack.mitre.org/techniques/T1574/006/.
func joinTechniqueLinks(techs []string) string {
	out := make([]string, len(techs))
	for i, t := range techs {
		urlPath := strings.ReplaceAll(t, ".", "/")
		out[i] = fmt.Sprintf("[`%s`](https://attack.mitre.org/techniques/%s/)", t, urlPath)
	}
	return strings.Join(out, ", ")
}

func joinCode(xs []string) string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = "`" + x + "`"
	}
	return strings.Join(out, ", ")
}
