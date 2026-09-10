// Command attacktable regenerates the UI's ATT&CK technique table from MITRE's published STIX bundle.
//
// The Coverage page has to render a technique's human name and group it under a tactic, and neither can be derived from our own
// rules. Sigma tags tactics at the RULE level and mixes them into one flat namespace with techniques and software ids, so a rule
// carrying `attack.persistence`, `attack.t1543.004` and `attack.s0402` says which tactics the RULE relates to, not which tactic
// that technique belongs to. Measured on this corpus, 38 of 61 techniques got conflicting answers that way. Technique-to-tactic
// is a fact about ATT&CK, so it comes from ATT&CK.
//
// The generated table is committed. The 53MB bundle it is cut from is NOT: this vendors the extract, every live enterprise
// technique, so a build never depends on reaching MITRE and the exact data in use is readable in a diff.
//
// Not filtered to macOS, deliberately. The vendored upstream Sigma rules are macOS rules that nonetheless carry tags for
// Windows-only techniques (a chflags rule tagged T1564.004, NTFS File Attributes), and those rules are copied verbatim so the
// tag is not ours to correct. A platform filter left exactly those two unmapped. The whole enterprise set costs about 5KB
// gzipped more and removes the edge case.
//
// Usage:
//
//	go run ./tools/attacktable -bundle enterprise-attack-19.1.json
//
// Download the bundle from
// https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-<version>.json
// The version the generated file records must match navigatorATTACKVersion in server/rules/api/navigator.go, which is what the
// exported Navigator layer declares; `task lint:attack-version` checks that and that the version is still current.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// defaultOut is the generated file. It is TypeScript rather than Go because the Coverage page is the only consumer: the server
// emits a Navigator layer, whose format carries technique ids and no names by design (the Navigator resolves those itself).
const defaultOut = "ui/src/components/attack-techniques.generated.ts"

// attribution is required by the ATT&CK Terms of Use, which permit redistribution of derived data on the condition that MITRE's
// copyright designation is reproduced with it.
const attribution = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of " +
	"The MITRE Corporation."

type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type              string              `json:"type"`
	ID                string              `json:"id"`
	Name              string              `json:"name"`
	Revoked           bool                `json:"revoked"`
	Deprecated        bool                `json:"x_mitre_deprecated"`
	Shortname         string              `json:"x_mitre_shortname"`
	Version           string              `json:"x_mitre_version"`
	TacticRefs        []string            `json:"tactic_refs"`
	KillChainPhases   []killChainPhase    `json:"kill_chain_phases"`
	ExternalReference []externalReference `json:"external_references"`
}

type killChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type externalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

// technique is one generated row.
type technique struct {
	ID   string
	Name string
	// Tactics are the technique's tactic shortnames in the order ATT&CK lists them. A technique legitimately belongs to more
	// than one (T1053.003 is execution, persistence AND privilege-escalation), which is why this is not a single value.
	Tactics []string
}

func main() {
	bundlePath := flag.String("bundle", "", "path to a MITRE ATT&CK enterprise STIX bundle (required unless -check-latest)")
	out := flag.String("out", defaultOut, "generated TypeScript file to write")
	check := flag.Bool("check-latest", false, "check the vendored table against MITRE's newest published release and exit")
	flag.Parse()
	if *check {
		if err := checkLatest(*out); err != nil {
			fmt.Fprintf(os.Stderr, "attacktable: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *bundlePath == "" {
		fmt.Fprintln(os.Stderr, "attacktable: -bundle is required; see the package comment for where to download one")
		os.Exit(2)
	}
	if flag.NArg() > 0 {
		// Refuse a stray positional rather than silently ignoring it, so a mistyped flag cannot look like a successful run.
		fmt.Fprintf(os.Stderr, "attacktable: unexpected argument %q\n", flag.Arg(0))
		os.Exit(2)
	}
	if err := run(*bundlePath, *out); err != nil {
		fmt.Fprintf(os.Stderr, "attacktable: %v\n", err)
		os.Exit(1)
	}
}

func run(bundlePath, out string) error {
	raw, err := os.ReadFile(bundlePath) //nolint:gosec // operator-supplied path to a file they just downloaded
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	var bundle stixBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}
	version, tacticOrder, techniques, err := extract(bundle)
	if err != nil {
		return err
	}
	rendered := render(version, tacticOrder, techniques)
	if err := os.WriteFile(out, []byte(rendered), 0o644); err != nil { //nolint:gosec // generated source, not a secret
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("attacktable: wrote %s (ATT&CK v%s, %d tactics, %d techniques)\n",
		out, version, len(tacticOrder), len(techniques))
	return nil
}

// tacticName pairs a shortname with its display name, in matrix order.
type tacticName struct {
	Shortname string
	Display   string
}

// extract pulls the version, the canonical tactic order, and every live technique row out of a bundle.
func extract(bundle stixBundle) (version string, tactics []tacticName, techniques []technique, err error) {
	version, matrix := collectionVersionAndMatrix(bundle)
	if version == "" {
		return "", nil, nil, errors.New("bundle declares no x-mitre-collection version")
	}
	if matrix == nil {
		return "", nil, nil, errors.New("bundle has no enterprise matrix to take the tactic order from")
	}
	if tactics = orderedTactics(bundle, matrix); len(tactics) == 0 {
		return "", nil, nil, errors.New("matrix resolved no tactics")
	}
	if techniques = liveTechniques(bundle); len(techniques) == 0 {
		return "", nil, nil, errors.New("bundle yielded no techniques")
	}
	// Sorted so the generated file is byte-identical across runs and a regeneration diff shows only real ATT&CK changes.
	sort.Slice(techniques, func(a, b int) bool { return techniques[a].ID < techniques[b].ID })
	return version, tactics, techniques, nil
}

// collectionVersionAndMatrix finds the release version and the enterprise matrix in one pass over the bundle.
func collectionVersionAndMatrix(bundle stixBundle) (version string, matrix *stixObject) {
	for i, o := range bundle.Objects {
		switch {
		case o.Type == "x-mitre-collection" && version == "":
			version = o.Version
		case o.Type == "x-mitre-matrix" && !o.Revoked && matrix == nil:
			matrix = &bundle.Objects[i]
		}
	}
	return version, matrix
}

// orderedTactics resolves the matrix's tactic_refs into shortname/display pairs, IN MATRIX ORDER.
//
// The order is the point. It is the one every ATT&CK rendering uses, and sorting instead would put Impact before Initial
// Access. It is also where a stale hardcoded list gets caught: v19 replaced Defense Evasion with Stealth and Defense
// Impairment, so a table generated from v19 simply cannot carry the old vocabulary.
func orderedTactics(bundle stixBundle, matrix *stixObject) []tacticName {
	byID := make(map[string]stixObject, len(bundle.Objects))
	for _, o := range bundle.Objects {
		byID[o.ID] = o
	}
	tactics := make([]tacticName, 0, len(matrix.TacticRefs))
	for _, ref := range matrix.TacticRefs {
		t, ok := byID[ref]
		if !ok || t.Shortname == "" {
			continue
		}
		tactics = append(tactics, tacticName{Shortname: t.Shortname, Display: t.Name})
	}
	return tactics
}

// liveTechniques returns every technique the release still carries, dropping the revoked and deprecated ones so the table
// cannot name a technique ATT&CK has withdrawn.
func liveTechniques(bundle stixBundle) []technique {
	var techniques []technique
	for _, o := range bundle.Objects {
		if o.Type != "attack-pattern" || o.Revoked || o.Deprecated {
			continue
		}
		id := attackID(o)
		if id == "" {
			continue
		}
		var phases []string
		for _, p := range o.KillChainPhases {
			if p.KillChainName == "mitre-attack" {
				phases = append(phases, p.PhaseName)
			}
		}
		techniques = append(techniques, technique{ID: id, Name: o.Name, Tactics: phases})
	}
	return techniques
}

// attackID returns the technique's ATT&CK id (T1016, T1059.002) from its mitre-attack external reference.
func attackID(o stixObject) string {
	for _, r := range o.ExternalReference {
		if r.SourceName == "mitre-attack" {
			return r.ExternalID
		}
	}
	return ""
}

func render(version string, tactics []tacticName, techniques []technique) string {
	var b strings.Builder
	fmt.Fprintf(&b, `// Code generated by tools/attacktable. DO NOT EDIT.
//
// Source: MITRE ATT&CK Enterprise v%s, every live technique.
// Regenerate with: go run ./tools/attacktable -bundle enterprise-attack-%s.json
//
// %s
//
// Technique-to-tactic is a fact about ATT&CK and cannot be derived from our own rules: Sigma tags tactics at the rule level and
// mixes them with technique and software ids in one namespace, which gave 38 of 61 techniques conflicting answers when measured.
// Hand-maintaining this table is what produced the "Unmapped" rows it replaces: it held 12 entries against 65 techniques in use.

export interface TechniqueMeta {
  id: string;
  name: string;
  // The tactic this technique is grouped under, as a display name. A technique can belong to several (T1053.003 is Execution,
  // Persistence and Privilege Escalation); this is the first ATT&CK lists, and tactics carries the rest.
  tactic: string;
  tactics: string[];
}

// ATTACK_VERSION is the ATT&CK release this table was cut from. It must match navigatorATTACKVersion in
// server/rules/api/navigator.go, which is the version the exported Navigator layer declares.
export const ATTACK_VERSION = "%s";

// TACTIC_ORDER is the enterprise matrix order, taken from the matrix object rather than sorted: alphabetical would put Impact
// before Initial Access. v19 replaced Defense Evasion with Stealth and Defense Impairment.
export const TACTIC_ORDER: string[] = [
`, version, version, attribution, version)
	for _, t := range tactics {
		fmt.Fprintf(&b, "  %q,\n", t.Display)
	}
	b.WriteString("];\n\n")

	display := make(map[string]string, len(tactics))
	for _, t := range tactics {
		display[t.Shortname] = t.Display
	}
	b.WriteString("export const TECHNIQUE_CATALOG: Record<string, TechniqueMeta> = {\n")
	for _, t := range techniques {
		names := make([]string, 0, len(t.Tactics))
		for _, short := range t.Tactics {
			if d, ok := display[short]; ok {
				names = append(names, d)
			}
		}
		primary := ""
		if len(names) > 0 {
			primary = names[0]
		}
		quoted := make([]string, 0, len(names))
		for _, n := range names {
			quoted = append(quoted, fmt.Sprintf("%q", n))
		}
		fmt.Fprintf(&b, "  %q: { id: %q, name: %q, tactic: %q, tactics: [%s] },\n",
			t.ID, t.ID, t.Name, primary, strings.Join(quoted, ", "))
	}
	b.WriteString("};\n")
	return b.String()
}
