package api

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
)

// MITRE ATT&CK Navigator layer-document constants. Centralised here (rather than inlined at the build site) so the live
// GET /api/attack-coverage endpoint and the committed docs/attack-navigator-layer.json artifact share one source of truth and
// cannot drift in name, versions, or colour.
const (
	// navigatorLayerName is the layer's display title in the Navigator UI.
	navigatorLayerName = "Fleet EDR coverage"
	// navigatorLayerDescription is the layer's human-readable subtitle.
	navigatorLayerDescription = "MITRE ATT&CK techniques covered by currently-registered Fleet EDR detection rules. " +
		"Amber techniques are covered only by rules that raise no alert as shipped, whether because they record without alerting or are off by default."
	// navigatorDomain pins the layer to the enterprise matrix; combined with the macOS platform filter this renders only the
	// macOS columns Fleet EDR actually covers.
	navigatorDomain = "enterprise-attack"
	// navigatorCoveredScore is the score a technique gets when any rule covers it. Binary coverage (1) rather than a graded heat:
	// the catalog has no notion of "partial" coverage of a technique today.
	navigatorCoveredScore = 1.0
	// navigatorCoveredColor is the swatch the Navigator paints a covered technique. A mid green that reads as "we have this" on the
	// matrix without being garish.
	navigatorCoveredColor = "#31a354"
	// navigatorNotAlertingScore and navigatorNotAlertingColor mark a technique covered only by rules that do not alert as shipped
	// (issue #764). A distinct score keeps the two apart when the layer is read as data, and the amber keeps them apart when it is
	// read as a picture, which is how a coverage heatmap is usually read. Painting these the same green as an alerting rule would
	// make the product look like it raises something it does not.
	navigatorNotAlertingScore = 0.5
	navigatorNotAlertingColor = "#fdae6b"
	// navigatorPlatformMacOS is the canonical ATT&CK platform string Fleet EDR scopes the layer to. Fleet EDR is a macOS-only
	// product, so the layer filters the matrix to the macOS columns rather than rendering the full cross-platform enterprise grid.
	navigatorPlatformMacOS = "macOS"
	// navigatorATTACKVersion is the ATT&CK content version the layer is authored against. BUMP THIS on each ATT&CK release
	// (https://attack.mitre.org/resources/versions/): a stale value makes the Navigator prompt the operator to upgrade the
	// layer on import. The catalog's mapped technique IDs are verified to still exist (not deprecated/revoked) at this
	// version. Currently ATT&CK v19 (v19.1, released 2026-04-28).
	navigatorATTACKVersion = "19"
	// navigatorAppVersion is the Navigator application version the layer declares compatibility with. The v4.5 layer spec
	// requires >= "4.9.0"; track the current Navigator release so a v19 layer doesn't advertise a pre-v19 tool version.
	navigatorAppVersion = "5.2.0"
	// navigatorLayerFormatVersion is the Navigator layer file-format version. Still "4.5" as of Navigator 5.x / ATT&CK v19.
	navigatorLayerFormatVersion = "4.5"
)

// NavigatorTechnique is one technique entry in a Navigator layer document. Field tags are the layer-4.5 wire shape the upstream
// Navigator imports verbatim; renaming one is a contract break for both the endpoint and the committed artifact.
type NavigatorTechnique struct {
	TechniqueID string  `json:"techniqueID"`
	Score       float64 `json:"score"`
	Color       string  `json:"color,omitempty"`
	Comment     string  `json:"comment,omitempty"`
}

// NavigatorFilters carries the layer's platform scoping. Fleet EDR sets Platforms to the single macOS value so the Navigator
// renders only the macOS matrix.
type NavigatorFilters struct {
	Platforms []string `json:"platforms"`
}

// NavigatorLayer is a MITRE ATT&CK Navigator layer-4.5 document. It is the response body of GET /api/attack-coverage and the
// content of the committed docs/attack-navigator-layer.json artifact; both are produced by BuildNavigatorLayer so they decode
// to the same document (the serialized bytes differ: the endpoint is compact + HTML-escaped, the committed file is indented +
// HTML-unescaped). The UI's AttackNavigatorLayer interface mirrors this shape.
type NavigatorLayer struct {
	Name        string               `json:"name"`
	Versions    map[string]string    `json:"versions"`
	Domain      string               `json:"domain"`
	Description string               `json:"description"`
	Filters     NavigatorFilters     `json:"filters"`
	Techniques  []NavigatorTechnique `json:"techniques"`
}

// BuildNavigatorLayer assembles the Navigator layer document from the registered rule metadata. Output is deterministic:
// technique IDs and the per-technique covering-rule lists are sorted, and duplicate rule IDs (a rule declaring the same
// technique twice) are compacted, so the JSON is byte-identical across runs and safe to snapshot, ETag, and diff. A rules slice
// that declares no techniques yields a non-nil empty Techniques slice, so the document serialises `"techniques": []` rather than
// `null`, which the spec's no-rules contract requires.
func BuildNavigatorLayer(rules []RuleMetadata) NavigatorLayer {
	// technique -> rule IDs that cover it, and whether any of those rules alerts by default.
	//
	// The distinction is why this document can be shown to someone evaluating the product. A rule whose default mode is monitor
	// evaluates and records what it would have fired on, but persists no alert until an operator promotes it, so a technique
	// covered only by such rules is not covered in the sense a reader of a coverage heatmap assumes. Scoring both the same would
	// inflate the figure with sixty-six rules that, as shipped, raise nothing (issue #764).
	coverage := make(map[string][]string)
	alerting := make(map[string]bool)
	for _, rule := range rules {
		for _, t := range rule.Techniques {
			coverage[t] = append(coverage[t], rule.ID)
			if rule.DefaultMode != DetectionRuleModeMonitor && rule.DefaultMode != DetectionRuleModeDisabled {
				alerting[t] = true
			}
		}
	}

	techniqueIDs := make([]string, 0, len(coverage))
	for tid := range coverage {
		techniqueIDs = append(techniqueIDs, tid)
	}
	slices.Sort(techniqueIDs)

	techniques := make([]NavigatorTechnique, 0, len(techniqueIDs))
	for _, tid := range techniqueIDs {
		// coverage is a throwaway local map, so sorting and compacting its slices in place is safe and avoids a per-technique clone.
		ruleIDs := coverage[tid]
		slices.Sort(ruleIDs)
		ruleIDs = slices.Compact(ruleIDs)
		score, color, prefix := navigatorCoveredScore, navigatorCoveredColor, "Covered by: "
		if !alerting[tid] {
			// Deliberately not "monitor only": a rule can default to disabled as well, and calling that monitor would be wrong
			// twice over, since a disabled rule records nothing and is not waiting to be promoted. What the two share, and what
			// this document has to say, is that no rule covering this technique raises an alert as shipped.
			score, color = navigatorNotAlertingScore, navigatorNotAlertingColor
			prefix = "No rule covering this raises an alert as shipped. Covered by: "
		}
		techniques = append(techniques, NavigatorTechnique{
			TechniqueID: tid,
			Score:       score,
			Color:       color,
			Comment:     prefix + strings.Join(ruleIDs, ", "),
		})
	}

	return NavigatorLayer{
		Name:        navigatorLayerName,
		Versions:    map[string]string{"attack": navigatorATTACKVersion, "navigator": navigatorAppVersion, "layer": navigatorLayerFormatVersion},
		Domain:      navigatorDomain,
		Description: navigatorLayerDescription,
		Filters:     NavigatorFilters{Platforms: []string{navigatorPlatformMacOS}},
		Techniques:  techniques,
	}
}

// MarshalNavigatorLayerIndented renders a layer as the two-space-indented, newline-terminated JSON the committed artifact uses.
// The generator (tools/gen-attack-layer) and the drift test both call this, so the bytes they compare are produced by one code
// path. HTML escaping is disabled so the ampersand in the description (ATT&CK) is written as a literal `&`; with encoding/json's
// default HTML escaping it would be emitted as a six-character unicode escape sequence (backslash-u-0-0-2-6), which is valid but
// noisy in a committed, human-diffed file. The result is still valid JSON the Navigator imports cleanly. The live endpoint
// marshals the same struct compactly via its own JSON writer with HTML escaping left on, so it serves the escaped form; both
// decode to the same document.
func MarshalNavigatorLayerIndented(layer NavigatorLayer) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(layer); err != nil { // Encode appends the trailing newline.
		return nil, err
	}
	return buf.Bytes(), nil
}
