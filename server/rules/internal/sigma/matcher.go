package sigma

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Event supplies field values to the evaluator. The rules context implements it over our event payloads (issue #761); this package
// stays independent of how a field is stored so the evaluator can be tested against literal values.
//
// Field returns every value the event carries for name. Most fields are single-valued, but some are genuinely lists (an exec
// event's argv), and Sigma matches a list-valued field if ANY element matches. ok is false when the event has no such field at
// all, which is distinct from a field present but empty: `Image: ""` matches the latter and not the former.
type Event interface {
	Field(name string) (values []string, ok bool)
}

// valueTest is one compiled value on the right-hand side of a field matcher. Exactly one of its three forms is active, chosen at
// compile time so the hot path branches on a bool rather than re-inspecting the pattern text on every event.
type valueTest struct {
	lit  string         // literal comparand, case-folded compare; the active form when glob and re are nil
	glob *glob          // the active form when the value carries Sigma wildcard syntax, compiled at load (issue #787)
	re   *regexp.Regexp // set only by the |re modifier
}

func (v valueTest) match(s string) bool {
	switch {
	case v.re != nil:
		return v.re.MatchString(s)
	case v.glob != nil:
		return v.glob.match(s)
	default:
		return strings.EqualFold(s, v.lit)
	}
}

// fieldTest is one `Field|modifiers: values` entry.
//
// The default quantifier over values is ANY (Sigma's `Image|endswith: [a, b]` matches either), which the |all modifier flips to
// ALL. The quantifier over the EVENT's values is always ANY, and the two are independent: `argv|contains|all: [x, y]` asks that
// x and y each appear in some argument, not that they appear in the same one.
type fieldTest struct {
	field string
	tests []valueTest
	all   bool
	// absent is Sigma's `Field: null`, which matches when the event does not carry the field at all. 73 rules corpus-wide use it
	// (one on macOS, to drop browser-child execs that report no command line), which is an order of magnitude more than the
	// base64offset and cidr modifiers this evaluator deliberately omits.
	absent bool
}

func (f fieldTest) match(ev Event) bool {
	values, ok := ev.Field(f.field)
	if f.absent {
		// A field present but holding no values is as absent as one the event never carried; both mean "nothing to match here".
		// Distinct from `Field: ""`, which requires the field to be present AND empty, and is a separate rule in the corpus.
		return !ok || len(values) == 0
	}
	if !ok {
		return false
	}
	for _, t := range f.tests {
		matched := slices.ContainsFunc(values, t.match)
		if f.all && !matched {
			return false // every listed value must match somewhere
		}
		if !f.all && matched {
			return true // any listed value matching is enough
		}
	}
	// Falling out means all-matched (for |all) or none-matched (for the default). An empty value list matches nothing either way,
	// but compile rejects that shape before it can get here.
	return f.all
}

// search is one named search identifier. A Sigma search is either a map of field matchers (AND across the fields) or a list of
// such maps (OR across the list), so alternatives holds the OR and each inner slice holds the AND.
type search struct {
	name         string
	alternatives [][]fieldTest
}

func (s search) match(ev Event) bool {
	for _, alt := range s.alternatives {
		all := true
		for _, f := range alt {
			if !f.match(ev) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// knownModifiers is the modifier surface this evaluator implements, and the census that justifies each one is in the package
// comment. A modifier outside this set is a load error rather than a silent no-op: a rule whose modifier we ignored would still
// evaluate, and would match far more broadly than its author wrote, which produces confident wrong alerts rather than an obvious
// failure.
//
// A name outside this set is reported as ErrUnsupported, which treats it as a modifier we have not built rather than one Sigma
// does not define. That conflates a real gap (`windash`, `base64offset`, `cidr`) with a misspelling of a modifier we do
// implement, and it does so deliberately. Telling them apart needs an authoritative list of every modifier Sigma defines, which this package would then have
// to keep current forever; the first modifier Sigma adds that we had not heard of would be classified as invalid and would abort
// an entire corpus import. Declining one rule and naming the modifier in the reason is the cheaper error, and it is legible: a
// reader sees the modifier that stopped it either way.
var knownModifiers = map[string]bool{
	"contains":   true,
	"startswith": true,
	"endswith":   true,
	"re":         true,
	"all":        true,
}

// modifiers is the decoded `|`-separated modifier list from a field key.
type modifiers struct {
	wrap      func(string) string // substring transformation into a wildcard pattern, nil if none
	wrapName  string              // which substring modifier produced wrap, for error messages
	useRegexp bool
	all       bool
}

// parseModifiers decodes and validates the modifier list, rejecting every combination without a defined meaning. Split out from
// compileFieldTest so each function does one job: this one decides what the modifiers mean, the caller applies them to values.
func parseModifiers(field string, mods []string) (modifiers, error) {
	var m modifiers
	seen := make(map[string]bool, len(mods))
	for _, name := range mods {
		if !knownModifiers[name] {
			return modifiers{}, fmt.Errorf("%w: field %q uses modifier %q", ErrUnsupported, field, name)
		}
		if seen[name] {
			return modifiers{}, fmt.Errorf("field %q repeats modifier %q", field, name)
		}
		seen[name] = true

		switch name {
		case "all":
			m.all = true
		case "re":
			m.useRegexp = true
		default:
			// A substring modifier. Two of them on one field have no composed meaning in Sigma, and last-assignment-wins would
			// silently pick one: `Field|contains|startswith` and `Field|startswith|contains` would compile to different
			// matchers, both of them something the author did not write. Checked before this one replaces the recorded name.
			if m.wrapName != "" {
				return modifiers{}, fmt.Errorf("field %q combines substring modifiers %q and %q, which has no defined meaning",
					field, m.wrapName, name)
			}
			m.wrap, m.wrapName = substringWrappers[name], name
		}
	}
	if m.useRegexp && m.wrap != nil {
		return modifiers{}, fmt.Errorf("field %q combines |re with a substring modifier, which has no defined meaning", field)
	}
	return m, nil
}

// substringWrappers turn a modifier into the equivalent wildcard pattern. Sigma's substring modifiers are exactly sugar over
// wildcards, so expressing them this way leaves one matching primitive to get right instead of four.
var substringWrappers = map[string]func(string) string{
	"contains":   func(v string) string { return "*" + v + "*" },
	"startswith": func(v string) string { return v + "*" },
	"endswith":   func(v string) string { return "*" + v },
}

// compileFieldTest builds one matcher from a `Field|mod|mod` key and its value, which YAML gives us as a scalar or a list.
func compileFieldTest(key string, raw any) (fieldTest, error) {
	field, mods, _ := strings.Cut(key, "|")
	if field == "" {
		return fieldTest{}, fmt.Errorf("empty field name in %q", key)
	}
	var modNames []string
	if mods != "" {
		modNames = strings.Split(mods, "|")
	}
	m, err := parseModifiers(field, modNames)
	if err != nil {
		return fieldTest{}, err
	}
	ft := fieldTest{field: field, all: m.all}

	if raw == nil {
		if m.wrap != nil || m.useRegexp || m.all {
			return fieldTest{}, fmt.Errorf("field %q combines a null value with a modifier, which has no defined meaning", field)
		}
		ft.absent = true
		return ft, nil
	}
	if _, isList := raw.([]any); m.all && !isList {
		// |all quantifies over the listed values, so it says nothing about a single one. Accepting it would let a rule carry a
		// modifier that cannot change its meaning, which reads as a constraint the author does not actually have.
		return fieldTest{}, fmt.Errorf("field %q uses |all on a single value, which quantifies over nothing", field)
	}

	values, err := scalarList(raw)
	if err != nil {
		return fieldTest{}, fmt.Errorf("field %q: %w", field, err)
	}
	if len(values) == 0 {
		// An empty list matches nothing under ANY and everything under ALL, so it is always a mistake rather than a shorthand.
		return fieldTest{}, fmt.Errorf("field %q has no values", field)
	}
	for _, v := range values {
		t, err := compileValue(v, m.wrap, m.useRegexp)
		if err != nil {
			return fieldTest{}, fmt.Errorf("field %q: %w", field, err)
		}
		ft.tests = append(ft.tests, t)
	}
	return ft, nil
}

func compileValue(v string, wrap func(string) string, useRegexp bool) (valueTest, error) {
	if useRegexp {
		// Compiled verbatim: Sigma's |re carries a real regular expression, and case-insensitivity is the author's to request with
		// an inline (?i) flag. Folding it here would silently widen every imported rule that relies on case.
		re, err := regexp.Compile(v)
		if err != nil {
			return valueTest{}, fmt.Errorf("invalid regexp %q: %w", v, err)
		}
		return valueTest{re: re}, nil
	}
	if wrap != nil {
		v = wrap(v)
	}
	if hasWildcard(v) {
		// Split into star-separated segments here, at load, so the per-event path never re-reads the pattern's escapes and never
		// backtracks. See glob.go for what that bounds.
		g := compileGlob(v)
		// lit is left empty: the compiled form is what decides, and keeping the raw pattern beside it would leave two
		// representations of one value with nothing keeping them in step.
		return valueTest{glob: &g}, nil
	}
	return valueTest{lit: v}, nil
}

// scalarList normalises a YAML value into the list of strings Sigma compares against. Sigma values are usually strings but the
// corpus also carries bare integers (a port, a uid), and YAML decodes those as int, so they are rendered rather than rejected.
func scalarList(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, err := scalarString(e)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	default:
		s, err := scalarString(raw)
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
}

func scalarString(raw any) (string, error) {
	switch v := raw.(type) {
	case string:
		return v, nil
	case int:
		return strconv.Itoa(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(v), nil
	default:
		return "", fmt.Errorf("unsupported value type %T", raw)
	}
}
