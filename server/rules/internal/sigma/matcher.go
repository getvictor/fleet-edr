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
// all, which is distinct from a field present but empty: `Image: ”` matches the latter and not the former.
type Event interface {
	Field(name string) (values []string, ok bool)
}

// valueTest is one compiled value on the right-hand side of a field matcher. Exactly one of its three forms is active, chosen at
// compile time so the hot path branches on a bool rather than re-inspecting the pattern text on every event.
type valueTest struct {
	lit  string         // literal comparand, case-folded compare, when wild and re are unset
	wild bool           // lit carries Sigma wildcard syntax and needs matchWildcard
	re   *regexp.Regexp // set only by the |re modifier
}

func (v valueTest) match(s string) bool {
	switch {
	case v.re != nil:
		return v.re.MatchString(s)
	case v.wild:
		return matchWildcard(s, v.lit)
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
		// Distinct from `Field: ''`, which requires the field to be present AND empty, and is a separate rule in the corpus.
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
var knownModifiers = map[string]bool{
	"contains":   true,
	"startswith": true,
	"endswith":   true,
	"re":         true,
	"all":        true,
}

// compileFieldTest builds one matcher from a `Field|mod|mod` key and its value, which YAML gives us as a scalar or a list.
func compileFieldTest(key string, raw any) (fieldTest, error) {
	parts := strings.Split(key, "|")
	ft := fieldTest{field: parts[0]}
	if ft.field == "" {
		return fieldTest{}, fmt.Errorf("empty field name in %q", key)
	}

	var wrap func(string) string
	useRegexp := false
	for _, m := range parts[1:] {
		if !knownModifiers[m] {
			return fieldTest{}, fmt.Errorf("field %q uses unsupported modifier %q", ft.field, m)
		}
		switch m {
		case "all":
			ft.all = true
		case "re":
			useRegexp = true
		case "contains":
			wrap = func(v string) string { return "*" + v + "*" }
		case "startswith":
			wrap = func(v string) string { return v + "*" }
		case "endswith":
			wrap = func(v string) string { return "*" + v }
		}
	}
	if useRegexp && wrap != nil {
		return fieldTest{}, fmt.Errorf("field %q combines |re with a substring modifier, which has no defined meaning", ft.field)
	}

	if raw == nil {
		if wrap != nil || useRegexp || ft.all {
			return fieldTest{}, fmt.Errorf("field %q combines a null value with a modifier, which has no defined meaning", ft.field)
		}
		ft.absent = true
		return ft, nil
	}

	values, err := scalarList(raw)
	if err != nil {
		return fieldTest{}, fmt.Errorf("field %q: %w", ft.field, err)
	}
	if len(values) == 0 {
		// An empty list matches nothing under ANY and everything under ALL, so it is always a mistake rather than a shorthand.
		return fieldTest{}, fmt.Errorf("field %q has no values", ft.field)
	}
	for _, v := range values {
		t, err := compileValue(v, wrap, useRegexp)
		if err != nil {
			return fieldTest{}, fmt.Errorf("field %q: %w", ft.field, err)
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
	return valueTest{lit: v, wild: hasWildcard(v)}, nil
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
