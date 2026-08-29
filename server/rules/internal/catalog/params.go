package catalog

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

// packFS is the rule pack: one declarative file per detection.
//
// It lives here, inside the package that reads it, rather than under docs/. A go:embed pattern cannot contain "..", so a package
// under server/rules/ simply cannot embed a directory at the repository root; the only way to keep the pack in docs/ would be a
// second, generated copy. That is the arrangement in issue #781, where the embedded OpenAPI spec drifted 49 lines from its
// canonical source because the go:generate that syncs them is wired to nothing. One canonical location, read by the code that
// owns it, has no such failure mode. docs/rules/README.md points here.
//
//go:embed pack/*.yml
var packFS embed.FS

// SharedListsFile is the pack file holding list definitions more than one rule matches against. It is authored, not generated,
// so the rule-file generator must neither overwrite nor prune it; the name is exported for that reason.
const SharedListsFile = "lists.yml"

// paramKind is the type a param's value must parse as. Kinds are deliberately few: every value the rules read today is a set of
// strings or a duration, and inventing kinds for values nothing uses would be speculative.
type paramKind int

const (
	kindStringList paramKind = iota
	kindDuration
)

// paramSpec declares one param of one algorithm.
//
// ReadOnly marks a value an operator may read but not change. That is not the same as leaving it out of the file: inspectability
// is the point of the pack, so an analyst must be able to see that osascript_network_exec matches /usr/bin/osascript even though
// changing it would not tune the rule, it would make the rule something other than what its name says.
type paramSpec struct {
	kind     paramKind
	readOnly bool
}

// algorithmParams registers, per algorithm, exactly the params that algorithm's code reads.
//
// Keying on the ALGORITHM rather than the rule is what makes two rules registered against one algorithm unable to disagree about
// what is overridable. It also makes a param name mean one thing per algorithm and lets the same name mean something else in
// another, which is correct and must not be reconciled: `window` is the ancestor-walk bound in ancestor_walk_path_prefix and the
// descendant-walk bound in descendant_within_window. They are both 30s by coincidence, and collapsing them into one value would
// couple two algorithms that have no reason to move together.
//
// dns_resolve_then_connect is absent because dns_c2_beacon was outside this step's scope; its window and DGA thresholds are still
// Go constants. Moving them needs integer and float parameter kinds, which nothing else uses yet.
//
// A name absent from this map is rejected at load. Dead config that no code consults is worse than a missing key, because it
// invites an operator to believe they have tuned something.
//
// Two lists are deliberately NOT here yet, and stay Go constants: the shell path set (shared by ancestor_walk_path_prefix and
// parent_lookup_path_match), the shebang-shell set (shared by descendant_within_window and ancestor_walk_path_prefix) and the world-writable prefix set (shared by ancestor_walk_path_prefix, dns_resolve_then_connect and
// descendant_within_window, through isSuspiciousPath). Moving a shared list into per-algorithm params would copy it into five
// files that nothing keeps equal, which is a worse state than the single Go variable they are today. They move when a shared-list
// mechanism exists (issue #759), whose "a third rule needs the same list" trigger the prefix set has already met.
//
// Params that feed RETRIEVAL rather than the decision are deliberately absent from both this map and the files: the ingest and
// skew pads, the ancestor-walk and descendant caps, the DNS port. Raising them changes no finding and merely widens a scan;
// lowering them causes silent false negatives. There is no setting that improves detection, which is why they stay constants in
// the algorithm's own code.
var algorithmParams = map[string]map[string]paramSpec{
	"ancestor_walk_path_prefix": {
		"window": {kind: kindDuration},
	},
	"descendant_within_window": {
		// Rule identity: changing what counts as osascript, or which shells the kernel exec()s for a shebang, does not tune this
		// rule. Readable, not writable.
		"osascript_paths":   {kind: kindStringList, readOnly: true},
		"download_binaries": {kind: kindStringList},
		"window":            {kind: kindDuration},
	},
	"parent_lookup_path_match": {
		"office_binaries": {kind: kindStringList},
	},
	"exec_path_and_subcommand_match": {
		"security_paths":     {kind: kindStringList, readOnly: true},
		"dump_keychain_args": {kind: kindStringList},
	},
	"exec_subcommand_and_path_pattern_match": {
		"launchctl_paths": {kind: kindStringList, readOnly: true},
	},
}

// Params is one rule's parameter block, parsed from its pack file.
//
// It keeps the raw YAML node alongside the parsed values so the generator can re-emit the block verbatim. That is what preserves
// the comments explaining why a threshold is what it is, which are the most valuable thing in the block and would be lost by
// re-rendering from parsed values.
type Params struct {
	raw    *yaml.Node
	lists  map[string][]string
	durs   map[string]time.Duration
	ruleID string
}

// Raw returns the verbatim params node for re-emission, or nil when the rule declares none.
func (p *Params) Raw() *yaml.Node {
	if p == nil {
		return nil
	}
	return p.raw
}

// StringSet returns a param as a set, the shape the rules match against. Panics on a name the rule does not declare: every
// lookup is a literal in rule code checked against the schema at load, so a miss is a programming error and not a runtime
// condition an operator can cause.
func (p *Params) StringSet(name string) map[string]bool {
	// A nil receiver means the rule id is absent from the pack. paramsFor never returns nil, so this is reachable only by indexing
	// the pack map directly, which tests do; panicking beats a nil dereference, and it is what nilaway asks for.
	if p == nil {
		panic(fmt.Sprintf("catalog: no params loaded for the rule holding string-list param %q", name))
	}
	list, ok := p.lists[name]
	if !ok {
		panic(fmt.Sprintf("catalog: rule %s has no string-list param %q", p.ruleID, name))
	}
	out := make(map[string]bool, len(list))
	for _, v := range list {
		out[v] = true
	}
	return out
}

// StringList returns a param as an ordered slice, for the matches that care about order (prefix scans).
func (p *Params) StringList(name string) []string {
	// A nil receiver means the rule id is absent from the pack. paramsFor never returns nil, so this is reachable only by indexing
	// the pack map directly, which tests do; panicking beats a nil dereference, and it is what nilaway asks for.
	if p == nil {
		panic(fmt.Sprintf("catalog: no params loaded for the rule holding string-list param %q", name))
	}
	list, ok := p.lists[name]
	if !ok {
		panic(fmt.Sprintf("catalog: rule %s has no string-list param %q", p.ruleID, name))
	}
	return list
}

// Duration returns a duration param.
func (p *Params) Duration(name string) time.Duration {
	// A nil receiver means the rule id is absent from the pack. paramsFor never returns nil, so this is reachable only by indexing
	// the pack map directly, which tests do; panicking beats a nil dereference, and it is what nilaway asks for.
	if p == nil {
		panic(fmt.Sprintf("catalog: no params loaded for the rule holding duration param %q", name))
	}
	d, ok := p.durs[name]
	if !ok {
		panic(fmt.Sprintf("catalog: rule %s has no duration param %q", p.ruleID, name))
	}
	return d
}

// packFile is the subset of a rule file the loader reads. Everything else in the file is generated from Doc() and is of no
// interest here.
type packFile struct {
	Engine struct {
		RuleID    string `yaml:"rule_id"`
		Algorithm string `yaml:"algorithm"`
		// A VALUE yaml.Node, not a pointer. yaml.v3 captures a subtree only into the value type: decoding into *yaml.Node
		// allocates a zero node and leaves it empty, which reads at every call site as "the rule declared no params".
		Params yaml.Node `yaml:"params"`
	} `yaml:"x-engine"`
}

// pack returns every rule's params, keyed by rule id, loading the embedded files once on first use.
//
// A failure here is a malformed EMBEDDED file: the bytes cannot change after compilation, so it is a programming error rather
// than a runtime condition an operator can cause, and panicking is consistent with the package-level regexp.MustCompile calls the
// rules already use.
//
// It is deliberately LAZY rather than a package-level initialiser. An eager `var pack = mustLoadPack()` panics during package
// init, which happens before any test runs: a single malformed file would make the whole package untestable, so the one test
// that could tell you what was wrong could never execute. Deferring to first use keeps loadPack directly testable against
// fixtures while still failing the server at boot, since the first rule construction happens there.
var pack = sync.OnceValue(func() map[string]*Params {
	p, err := loadPack(packFS)
	if err != nil {
		panic("catalog: rule pack failed to load: " + err.Error())
	}
	return p
})

// sharedLists returns the shared list definitions, loaded once alongside the pack.
//
// A list lives here rather than in a rule's params when MORE THAN ONE rule matches against it. Splitting such a list into
// per-rule params would copy it into every consumer's file with nothing keeping the copies equal, which is strictly worse than
// the single Go variable each of these was before. What reads the value decides where it lives: a rule's own code reads a param,
// and code shared across rules reads a shared list.
var sharedLists = sync.OnceValue(func() map[string][]string {
	l, err := loadSharedLists(packFS)
	if err != nil {
		panic("catalog: shared lists failed to load: " + err.Error())
	}
	return l
})

func loadSharedLists(fsys fs.FS) (map[string][]string, error) {
	body, err := fs.ReadFile(fsys, "pack/"+SharedListsFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", SharedListsFile, err)
	}
	var out map[string][]string
	if err := yaml.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", SharedListsFile, err)
	}
	for name, list := range out {
		if len(list) == 0 {
			return nil, fmt.Errorf("%s: list %q is empty", SharedListsFile, name)
		}
	}
	return out, nil
}

// sharedList returns one shared list. Panics on an unknown name: every lookup is a literal in rule code, so a miss is a
// programming error rather than a runtime condition an operator can cause, and failing at boot is the point.
func sharedList(name string) []string {
	list, ok := sharedLists()[name]
	if !ok {
		panic(fmt.Sprintf("catalog: no shared list %q in %s", name, SharedListsFile))
	}
	return list
}

// sharedSet returns one shared list as a set, the shape most match sites want.
func sharedSet(name string) map[string]bool {
	list := sharedList(name)
	out := make(map[string]bool, len(list))
	for _, v := range list {
		out[v] = true
	}
	return out
}

// MustLoadPack forces the embedded pack and shared lists to load, panicking if either is malformed.
//
// Called from New so a malformed pack fails at start-up. Without it the lazy accessors are first touched during evaluation, so a
// bad value would let the server boot and then panic on the first detection: the exact "fails at first fire rather than at boot"
// behaviour the validation exists to prevent.
func MustLoadPack() {
	pack()
	sharedLists()
}

// loadPack parses every rule file in fsys and validates each params block against its algorithm's schema.
//
// Validation is at LOAD, so a bad value fails at boot with a message naming the rule rather than at first fire, hours later, on
// one host, as a detection that silently did not happen.
func loadPack(fsys fs.FS) (map[string]*Params, error) {
	entries, err := fs.Glob(fsys, "pack/*.yml")
	if err != nil {
		return nil, fmt.Errorf("glob pack: %w", err)
	}
	sort.Strings(entries)

	out := make(map[string]*Params, len(entries))
	for _, name := range entries {
		// The shared-list definitions sit in the pack but are not a rule.
		if path.Base(name) == SharedListsFile {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		var f packFile
		if err := yaml.Unmarshal(body, &f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		if f.Engine.RuleID == "" {
			return nil, fmt.Errorf("%s: x-engine.rule_id is empty", name)
		}
		p, err := bindParams(f.Engine.RuleID, f.Engine.Algorithm, &f.Engine.Params)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if _, dup := out[f.Engine.RuleID]; dup {
			return nil, fmt.Errorf("%s: duplicate rule_id %q; the later file would silently replace the earlier rule's params", name, f.Engine.RuleID)
		}
		out[f.Engine.RuleID] = p
	}
	return out, nil
}

// bindParams parses one rule's params against its algorithm's schema.
func bindParams(ruleID, algorithm string, node *yaml.Node) (*Params, error) {
	schema, known := algorithmParams[algorithm]
	if node != nil && node.Kind != 0 && node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("rule %s: params must be a mapping", ruleID)
	}
	if node == nil || node.Kind == 0 || len(node.Content) == 0 {
		// A rule with no params is fine: most detections are a fixed predicate with nothing to tune. It is only an error for the
		// algorithm to declare params the file then omits, which is checked below against an empty set.
		if len(schema) > 0 {
			return nil, fmt.Errorf("rule %s declares no params, but algorithm %s requires %s", ruleID, algorithm, sortedNames(schema))
		}
		return &Params{ruleID: ruleID}, nil
	}
	if !known {
		return nil, fmt.Errorf("rule %s carries params, but algorithm %q registers none", ruleID, algorithm)
	}

	p := &Params{
		raw:    node,
		lists:  map[string][]string{},
		durs:   map[string]time.Duration{},
		ruleID: ruleID,
	}
	seen := map[string]bool{}
	// A YAML mapping node alternates key, value across Content.
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, val := node.Content[i].Value, node.Content[i+1]
		if seen[key] {
			return nil, fmt.Errorf("rule %s sets param %q twice; the later value would silently win", ruleID, key)
		}
		spec, ok := schema[key]
		if !ok {
			return nil, fmt.Errorf("rule %s sets param %q, which algorithm %s never reads", ruleID, key, algorithm)
		}
		seen[key] = true
		if err := bindOne(p, key, spec, val); err != nil {
			return nil, fmt.Errorf("rule %s param %q: %w", ruleID, key, err)
		}
	}
	for name := range schema {
		if !seen[name] {
			return nil, fmt.Errorf("rule %s omits param %q, which algorithm %s reads", ruleID, name, algorithm)
		}
	}
	return p, nil
}

func bindOne(p *Params, key string, spec paramSpec, val *yaml.Node) error {
	switch spec.kind {
	case kindStringList:
		var list []string
		if err := val.Decode(&list); err != nil {
			return fmt.Errorf("expected a list of strings: %w", err)
		}
		if len(list) == 0 {
			return errors.New("expected a non-empty list of strings")
		}
		p.lists[key] = list
	case kindDuration:
		var s string
		if err := val.Decode(&s); err != nil {
			return fmt.Errorf("expected a duration string such as 30s: %w", err)
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("expected a duration string such as 30s: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("expected a positive duration, got %s", s)
		}
		p.durs[key] = d
	}
	return nil
}

func sortedNames(schema map[string]paramSpec) []string {
	out := make([]string, 0, len(schema))
	for k := range schema {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// paramsFor returns the loaded params for a rule, or an empty set when it declares none.
func paramsFor(ruleID string) *Params {
	if p, ok := pack()[ruleID]; ok {
		return p
	}
	return &Params{ruleID: ruleID}
}

// ParamsNode returns the verbatim params block for a rule, or nil when it declares none.
//
// Exported so the rule-file generator can re-emit the block exactly as authored. Params are the one part of a rule file that is
// NOT derived from Go: they are the source of truth the rules read. Re-rendering them from parsed values would silently drop the
// comments that explain why a threshold is what it is, which is the most valuable content in the block.
func ParamsNode(ruleID string) *yaml.Node {
	return paramsFor(ruleID).Raw()
}
