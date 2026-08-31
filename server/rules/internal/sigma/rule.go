package sigma

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// ErrUnsupported marks a compile failure that means "this is valid Sigma, and this evaluator does not implement it" as opposed to
// "this rule is broken". Compile returns errors of both kinds and a caller usually has to act on them differently: a rule using a
// construct we have not built is one to decline and count, while a malformed rule is a defect in the rule file itself.
//
// The distinction is drawn here rather than by a caller matching on message text, because only this package knows which of its
// refusals are gaps in the implementation. Wrapped by exactly five refusals today: a reserved detection key, a keyword search, an
// unknown field modifier, a condition nested past the depth bound, and a list-valued condition. Everything else Compile rejects is
// malformed.
var ErrUnsupported = errors.New("unsupported Sigma feature")

// Rule is a compiled Sigma detection: the named searches and the condition that combines them. Compile it once at load; Matches
// is then allocation-free and safe to call concurrently.
type Rule struct {
	searches []search
	cond     node
}

// reservedDetectionKeys are Sigma keys that appear inside a `detection:` block but are not searches. `timeframe` belongs to the
// aggregation and correlation surface this evaluator does not implement (zero corpus rules use it), and `condition` is handled
// separately. Refusing them by name means an unsupported construct fails loudly rather than being compiled as an ordinary search.
var reservedDetectionKeys = map[string]bool{
	"timeframe": true,
}

// listCondition reports why a list-valued condition cannot be compiled, which is not always the same reason.
//
// Sigma's list form is a non-empty list of condition STRINGS, meaning their disjunction, and that is the form this evaluator has
// not built. A list that is empty, or that carries anything else, is not that form and not a condition at all, so it is a broken
// rule. Treating every list as the unsupported form would let `condition: [7]` load as a rejection and go green.
func listCondition(entries []any) error {
	if len(entries) == 0 {
		return errors.New("condition is an empty list, so nothing decides whether the rule fires")
	}
	for _, entry := range entries {
		if _, ok := entry.(string); !ok {
			return fmt.Errorf("condition list entries must be strings, got %T", entry)
		}
	}
	return fmt.Errorf("%w: condition is a list of %d conditions, meaning their disjunction", ErrUnsupported, len(entries))
}

// conditionString extracts the condition text, naming each way a `detection:` block can fail to carry one.
//
// Sigma defines two condition forms: a string, and a list of strings meaning their disjunction. This evaluator implements only the
// first, so a list is a gap rather than a defect: no rule in the corpus uses it, and guessing at it would be worse than declining
// it. A condition of any other type is neither form Sigma defines, so that one is a broken rule, as is a block carrying none.
func conditionString(raw any, present bool) (string, error) {
	if !present {
		return "", errors.New("detection block has no condition")
	}
	switch c := raw.(type) {
	case string:
		return c, nil
	case []any:
		return "", listCondition(c)
	default:
		return "", fmt.Errorf("condition must be a single string or a list of strings, got %T", raw)
	}
}

// Compile turns a decoded Sigma `detection:` block into an evaluable rule.
//
// Everything that can be wrong with a rule is rejected here rather than at match time: an unknown modifier, a condition naming a
// search that does not exist, a quantifier whose glob matches nothing, an empty value list. The alternative is a rule that loads
// clean and then quietly never fires, which is indistinguishable from "the adversary behaviour did not occur" and is therefore
// the worst failure this package can have.
func Compile(detection map[string]any) (*Rule, error) {
	rawCondition, present := detection["condition"]
	conditionText, err := conditionString(rawCondition, present)
	if err != nil {
		return nil, err
	}

	// Sorted so glob resolution, and any error naming a search, are deterministic: Go randomises map iteration order.
	names := make([]string, 0, len(detection))
	for name := range detection {
		if name == "condition" {
			continue
		}
		if reservedDetectionKeys[name] {
			// A reserved key is not a search. Collected as one it would be compiled as a field map and, worse, swept into any
			// `1 of` / `all of` quantifier, so the rule would evaluate a condition nobody wrote instead of being refused for
			// using a construct this evaluator does not implement.
			return nil, fmt.Errorf("%w: detection block uses reserved key %q", ErrUnsupported, name)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) == 0 {
		return nil, errors.New("detection block defines no searches")
	}

	r := &Rule{searches: make([]search, 0, len(names))}
	for _, name := range names {
		s, err := compileSearch(name, detection[name])
		if err != nil {
			return nil, err
		}
		r.searches = append(r.searches, s)
	}

	p := &parser{tokens: tokenize(conditionText), names: names}
	cond, err := p.parseCondition()
	if err != nil {
		return nil, fmt.Errorf("condition %q: %w", conditionText, err)
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("condition %q: unexpected trailing %q", conditionText, p.tokens[p.pos])
	}
	r.cond = cond
	return r, nil
}

// Matches reports whether the event satisfies the rule.
func (r *Rule) Matches(ev Event) bool { return r.cond.eval(r, ev) }

// Fields returns every event field the rule reads, sorted and deduplicated. The rules context uses it to check a rule against the
// taxonomy at load, so a rule naming a field we do not supply fails at start-up rather than never matching (issue #760).
func (r *Rule) Fields() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range r.searches {
		for _, alt := range s.alternatives {
			for _, f := range alt {
				if !seen[f.field] {
					seen[f.field] = true
					out = append(out, f.field)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// listSearchMaps classifies a list-valued search and returns its field maps.
//
// Sigma defines two list forms and they are not interchangeable: a list of field maps is a disjunction of alternatives, and a list
// of bare strings is a keyword search, matching the whole event rather than a named field. The classification is made over the
// WHOLE list rather than entry by entry, because a list mixing the two forms is neither of them. Deciding per entry would let the
// first string in a corrupted list report the file as merely using a keyword search, which downgrades a broken rule to a feature
// this evaluator has not built, and a caller importing a corpus acts on that difference.
//
// Zero macOS rules use a keyword search and this evaluator has no whole-event surface, so that form is a gap, marked unsupported.
// A mixed list, or one carrying an entry of any other type, is a malformed rule.
func listSearchMaps(name string, entries []any) ([]map[string]any, error) {
	fieldMaps := make([]map[string]any, 0, len(entries))
	keywords := 0
	for _, entry := range entries {
		switch e := entry.(type) {
		case map[string]any:
			fieldMaps = append(fieldMaps, e)
		case string:
			keywords++
		default:
			return nil, fmt.Errorf("search %q: list entries must be field maps, got %T", name, entry)
		}
	}
	switch {
	case keywords == len(entries) && keywords > 0:
		return nil, fmt.Errorf("%w: search %q is a keyword search", ErrUnsupported, name)
	case keywords > 0:
		return nil, fmt.Errorf("search %q mixes field maps with %d bare string(s), which is neither Sigma list form", name, keywords)
	}
	return fieldMaps, nil
}

// compileSearch builds one named search. A Sigma search is a map of field matchers (AND across fields) or a list of such maps
// (OR across the list).
func compileSearch(name string, raw any) (search, error) {
	s := search{name: name}
	switch v := raw.(type) {
	case map[string]any:
		alt, err := compileAlternative(name, v)
		if err != nil {
			return search{}, err
		}
		s.alternatives = append(s.alternatives, alt)
	case []any:
		maps, err := listSearchMaps(name, v)
		if err != nil {
			return search{}, err
		}
		for _, m := range maps {
			alt, err := compileAlternative(name, m)
			if err != nil {
				return search{}, err
			}
			s.alternatives = append(s.alternatives, alt)
		}
	default:
		return search{}, fmt.Errorf("search %q must be a field map or a list of field maps, got %T", name, raw)
	}
	if len(s.alternatives) == 0 {
		return search{}, fmt.Errorf("search %q is empty", name)
	}
	return s, nil
}

func compileAlternative(name string, m map[string]any) ([]fieldTest, error) {
	if len(m) == 0 {
		return nil, fmt.Errorf("search %q has an empty field map", name)
	}
	keys := slices.Sorted(maps.Keys(m))

	out := make([]fieldTest, 0, len(keys))
	for _, k := range keys {
		ft, err := compileFieldTest(k, m[k])
		if err != nil {
			return nil, fmt.Errorf("search %q: %w", name, err)
		}
		out = append(out, ft)
	}
	return out, nil
}
