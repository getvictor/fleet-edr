// gen-rule-docs renders docs/detection-rules.md from the structured Documentation
// each rule exposes via rules.api.Rule.Doc(). Run via:
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
	"net/url"
	"os"
	"strings"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
)

// allRegisteredRules delegates to rules.bootstrap.CatalogOnly so the docs generator and the production server's main.go are guaranteed
// to walk the same set of rules in the same order. Documentation is not a function of a particular deployment's tuning: CatalogOnly
// builds the catalog with a nil exclusion resolver (no configured exclusions), which is what the rule structs treat as "no operator
// tuning yet."
func allRegisteredRules() []rulesapi.RuleMetadata {
	return rulesbootstrap.CatalogOnly().List()
}

func main() {
	out := flag.String("out", "docs/detection-rules.md", "destination markdown file")
	flag.Parse()

	if err := generate(*out); err != nil {
		log.Fatalf("%v", err)
	}
}

// generate is split out so the deferred close runs even on a render error. `main` calling log.Fatalf with a defer in scope leaves the
// file unclosed (gocritic exitAfterDefer); pulling the body up here makes the close happen before main exits.
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
func render(w io.Writer, rs []rulesapi.RuleMetadata) error {
	var b strings.Builder
	b.WriteString("# Detection rules\n\n")
	// Every rule carries a Source row since issue #765, so this line can no longer use the row's presence to mean "vendored":
	// it now says which VALUE means that, because "reproduced unmodified" is true of the upstream corpus and false of ours.
	b.WriteString("Every rule names a **Source**. `Fleet EDR` marks a rule this project wrote; any other value credits an ")
	b.WriteString("upstream project and that rule's own author, and those rules are reproduced unmodified. The upstream macOS ")
	b.WriteString("corpus comes from [SigmaHQ](https://github.com/SigmaHQ/sigma) under the ")
	b.WriteString("[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License).\n\n")
	b.WriteString("This page is generated from `tools/gen-rule-docs` by reading the\n")
	b.WriteString("`rulesapi.RuleMetadata.Doc` field on every rule registered in\n")
	b.WriteString("`server/cmd/fleet-edr-server/main.go`. To refresh after changing a\n")
	b.WriteString("rule's documentation, run:\n\n")
	b.WriteString("```sh\n")
	b.WriteString("go run ./tools/gen-rule-docs\n")
	b.WriteString("```\n\n")
	b.WriteString("Hand-edits to this file get overwritten on the next regeneration.\n\n")

	// Index: operators jumping in from a CVE or alert title want a fast
	// lookup. ID is what shows up in alert rows; title is the friendly name.
	// Upstream rules this sensor does not run, before the index, because a reader looking for a rule that is absent needs to find
	// out why here rather than concluding the import missed it. The reason names the telemetry a re-sync would need.
	if refused := rulesbootstrap.ImportedRejections(); len(refused) > 0 {
		b.WriteString("## Upstream rules not run\n\n")
		b.WriteString("These rules are carried in the vendored upstream corpus but are not registered, because this sensor cannot run them. ")
		b.WriteString("They are listed so an absent rule reads as a decision rather than an oversight.\n\n")
		b.WriteString("| File | Why not |\n| --- | --- |\n")
		for _, r := range refused {
			fmt.Fprintf(&b, "| `%s` | %s |\n", r.File, mdCell(r.Reason))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Index\n\n")
	// Mode is in the index rather than only in each rule's detail table because the question it answers, "does this actually raise
	// anything", is one a reader needs while scanning. Most of this catalog ships in monitor mode (issue #764) and a reader who
	// assumed otherwise would take the list for a list of alerts.
	b.WriteString("| Rule ID | Title | Severity | Default mode | ATT&CK |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, r := range rs {
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s | %s | %s | %s |\n",
			r.ID, anchor(r.ID),
			mdCell(r.Doc.Title), mdCell(r.Doc.Severity), mdCell(string(r.DefaultMode)),
			mdCell(strings.Join(r.Techniques, ", ")))
	}
	b.WriteString("\n")

	for _, r := range rs {
		writeRule(&b, r)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// writeRule is intentionally a thin sequencer over per-section helpers so each helper stays trivially testable and the whole function
// stays under the project cognitive-complexity cap (Sonar go:S3776). Adding a new section means adding a new helper + a single
// Fprintf-style call here.
func writeRule(b *strings.Builder, r rulesapi.RuleMetadata) {
	writeRuleHeading(b, r.ID, r.Doc)
	writeRuleMeta(b, r.ID, r.Doc, r.Techniques, r.DefaultMode, r.Origin)
	writeRuleDescription(b, r.Doc)
	writeRuleBulletSection(b, "Known false-positive sources", r.Doc.FalsePositives)
	writeRuleBulletSection(b, "Limitations", r.Doc.Limitations)
	// References last, mirroring the rule page's ordering. Present here and not only in the UI because RuleDetail's own doc
	// promises this markdown is generated from the same Doc() definitions and therefore stays aligned with it; adding a section
	// to one surface and not the other is exactly the drift that promise exists to prevent (issue #765, caught by Copilot).
	writeRuleReferences(b, r.Doc.References)
}

func writeRuleHeading(b *strings.Builder, id string, d rulesapi.Documentation) {
	fmt.Fprintf(b, "## %s\n\n", id)
	fmt.Fprintf(b, "**%s**  \n", d.Title)
	if d.Summary != "" {
		fmt.Fprintf(b, "%s\n\n", d.Summary)
	}
}

func writeRuleMeta(
	b *strings.Builder, id string, d rulesapi.Documentation, techs []string, mode rulesapi.DetectionRuleMode, origin string,
) {
	b.WriteString("| | |\n| --- | --- |\n")
	fmt.Fprintf(b, "| Rule ID | `%s` |\n", id)
	fmt.Fprintf(b, "| Severity | `%s` |\n", d.Severity)
	fmt.Fprintf(b, "| Default mode | `%s` |\n", mode)
	if origin != "" {
		fmt.Fprintf(b, "| Source | %s |\n", mdCell(origin))
	}
	if mode == rulesapi.DetectionRuleModeMonitor {
		b.WriteString("| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |\n")
	}
	if len(techs) > 0 {
		fmt.Fprintf(b, "| ATT&CK | %s |\n", joinTechniqueLinks(techs))
	}
	if len(d.EventTypes) > 0 {
		fmt.Fprintf(b, "| Event types | %s |\n", joinCode(d.EventTypes))
	}
	b.WriteString("\n")
}

func writeRuleDescription(b *strings.Builder, d rulesapi.Documentation) {
	if d.Description == "" {
		return
	}
	b.WriteString("### Description\n\n")
	b.WriteString(d.Description)
	b.WriteString("\n\n")
}

func writeRuleBulletSection(b *strings.Builder, heading string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s\n\n", heading)
	for _, it := range items {
		fmt.Fprintf(b, "- %s\n", it)
	}
	b.WriteString("\n")
}

// writeRuleReferences renders a rule's citations, and does NOT reuse writeRuleBulletSection because these are the only strings in
// this document that this project did not write.
//
// A reference is copied verbatim out of a vendored upstream file, so a value like `[citation](//attacker.example)` is markdown, not
// text: emitted into a raw bullet it renders as a working link that an operator has every reason to trust, and an embedded newline
// restructures the document around it. The UI already enforces the policy that only an http(s) URL becomes followable (see
// ui/src/urls.ts); this is the same policy on the surface that had none. Found by Qodo on #824.
func writeRuleReferences(b *strings.Builder, refs []string) {
	if len(refs) == 0 {
		return
	}
	b.WriteString("### References\n\n")
	for _, ref := range refs {
		fmt.Fprintf(b, "- %s\n", mdReference(ref))
	}
	b.WriteString("\n")
}

// mdReference renders one citation: a bare autolink when it is an absolute http(s) URL, an inert code span otherwise.
//
// A code span rather than backslash-escaping, because escaping means enumerating every construct a markdown dialect might honour
// and being wrong once is enough. Inside a span the only character with meaning is the backtick, so the fence is grown past the
// longest run in the value and the content cannot escape it.
func mdReference(ref string) string {
	ref = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(strings.TrimSpace(ref))
	if u, err := url.Parse(ref); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		// The RE-SERIALISED url, and only if the bytes about to be written cannot themselves break the autolink.
		//
		// Two things force this shape. Go's parser accepts trailing junk after a valid prefix, so
		// `https://safe.example/a ![pixel](https://attacker.example/p)` reports scheme https and host safe.example: echoing the
		// caller's string back renders the attacker's image. And String() does NOT re-encode uniformly. Measured: the path and
		// the fragment are percent-encoded, but RawQuery is emitted verbatim, so `https://safe.example/?q=>[x](...)` keeps its
		// `>` and closes the autolink from inside.
		//
		// Hence the final check is on the OUTPUT rather than on the input or the parse. Anything that could terminate the form
		// (an angle bracket, whitespace, a control byte) means this value does not get to be a link, whichever component it came
		// from and whichever components a future Go release decides to encode differently.
		if s := u.String(); !breaksAutolink(s) {
			return "<" + s + ">"
		}
	}
	if ref == "" {
		return "``"
	}
	fence := strings.Repeat("`", longestBacktickRun(ref)+1)
	// Padding only when the content touches the fence. A span whose content starts or ends with a backtick needs the spaces (the
	// renderer strips them back off); adding them unconditionally would put visible padding inside every ordinary citation.
	if strings.HasPrefix(ref, "`") || strings.HasSuffix(ref, "`") {
		return fence + " " + ref + " " + fence
	}
	return fence + ref + fence
}

// breaksAutolink reports whether s contains a byte that would terminate a markdown autolink from inside it.
//
// CommonMark defines an autolink as `<`, an absolute URI, `>`, where the URI contains no whitespace and no angle bracket. So this
// is the complete set: anything here means the `<...>` wrapper cannot safely hold s, and the caller falls back to an inert span.
//
// Both reachable halves are exercised by the tests, and each is reachable only through RawQuery, which String() emits verbatim
// while it percent-encodes the same byte in the path or the fragment: `?q=>x` keeps its angle bracket and `?q=a b` keeps its
// space. Control bytes below 0x20 are covered by the same comparison but are unreachable in practice, since url.Parse rejects
// them outright; they cost nothing to include and remove a thing to be wrong about later.
func breaksAutolink(s string) bool {
	for _, c := range s {
		if c == '<' || c == '>' || c <= ' ' {
			return true
		}
	}
	return false
}

// longestBacktickRun reports the length of the longest consecutive backtick sequence in s, which is what a code-span fence has to
// exceed to contain it.
func longestBacktickRun(s string) int {
	best, run := 0, 0
	for _, c := range s {
		if c == '`' {
			run++
			best = max(best, run)
			continue
		}
		run = 0
	}
	return best
}

// mdCell escapes a string for safe insertion into a markdown table cell. Pipes have to be backslash-escaped or they end the column;
// newlines have to become <br> or they break the row. Today's Doc() values are well-behaved, but a future operator who pastes a
// paragraph containing either character into a Description should not silently corrupt the generated markdown.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", "<br>")
	return s
}

// anchor produces the GitHub-flavoured-markdown anchor slug for a heading. Our heading is the bare rule ID, which is already lowercase
// + underscored + ASCII, so the slug is the ID verbatim. Centralised so a future ID with less-friendly characters has one place to
// fix.
func anchor(id string) string { return id }

// joinTechniqueLinks renders each technique ID as a link to its MITRE page. Sub-techniques (e.g. T1574.006) need the dot translated to
// a slash in the URL path: attack.mitre.org/techniques/T1574/006/.
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
