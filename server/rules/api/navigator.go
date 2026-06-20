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
	navigatorLayerDescription = "MITRE ATT&CK techniques covered by currently-registered Fleet EDR detection rules."
	// navigatorDomain pins the layer to the enterprise matrix; combined with the macOS platform filter this renders only the
	// macOS columns Fleet EDR actually covers.
	navigatorDomain = "enterprise-attack"
	// navigatorCoveredScore is the score a technique gets when any rule covers it. Binary coverage (1) rather than a graded heat:
	// the catalog has no notion of "partial" coverage of a technique today.
	navigatorCoveredScore = 1
	// navigatorCoveredColor is the swatch the Navigator paints a covered technique. A mid green that reads as "we have this" on the
	// matrix without being garish.
	navigatorCoveredColor = "#31a354"
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
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Color       string `json:"color,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// NavigatorFilters carries the layer's platform scoping. Fleet EDR sets Platforms to the single macOS value so the Navigator
// renders only the macOS matrix.
type NavigatorFilters struct {
	Platforms []string `json:"platforms"`
}

// NavigatorLayer is a MITRE ATT&CK Navigator layer-4.5 document. It is the response body of GET /api/attack-coverage and the
// content of the committed docs/attack-navigator-layer.json artifact; both are produced by BuildNavigatorLayer so they stay
// byte-equivalent (modulo whitespace). The UI's AttackNavigatorLayer interface mirrors this shape.
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
	// technique -> rule IDs that cover it.
	coverage := make(map[string][]string)
	for _, rule := range rules {
		for _, t := range rule.Techniques {
			coverage[t] = append(coverage[t], rule.ID)
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
		techniques = append(techniques, NavigatorTechnique{
			TechniqueID: tid,
			Score:       navigatorCoveredScore,
			Color:       navigatorCoveredColor,
			Comment:     "Covered by: " + strings.Join(ruleIDs, ", "),
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
