package sigma

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// The searches the generated conditions draw from. Two prefixes so a glob quantifier selects a meaningful subset rather than
// everything, which is what makes `1 of sel_*` distinguishable from `1 of them`.
var pbtNames = []string{"sel_0", "sel_1", "sel_2", "flt_0", "flt_1"}

// refExpr is the reference interpretation: an independently evaluated boolean tree. The parser under test is correct exactly when
// its result agrees with this over every assignment, which is the property the issue asks for.
type refExpr interface {
	eval(assign map[string]bool) bool
	// render emits Sigma condition text. It parenthesises only where precedence requires it, so the generated text exercises the
	// parser's precedence rather than sidestepping it with parentheses everywhere.
	render() string
	prec() int // 0 = atom, 1 = not, 2 = and, 3 = or
}

type refRef struct{ name string }

func (e refRef) eval(a map[string]bool) bool { return a[e.name] }
func (e refRef) render() string              { return e.name }
func (e refRef) prec() int                   { return 0 }

// refQuant is `1 of <prefix>*` (any) or `all of <prefix>*` (every).
type refQuant struct {
	all    bool
	prefix string
}

func (e refQuant) eval(a map[string]bool) bool {
	seen := false
	for _, n := range pbtNames {
		if !strings.HasPrefix(n, e.prefix) {
			continue
		}
		seen = true
		if e.all && !a[n] {
			return false
		}
		if !e.all && a[n] {
			return true
		}
	}
	if !seen {
		return false
	}
	return e.all
}

func (e refQuant) render() string {
	q := "1"
	if e.all {
		q = "all"
	}
	return fmt.Sprintf("%s of %s*", q, e.prefix)
}
func (e refQuant) prec() int { return 0 }

type refNot struct{ inner refExpr }

func (e refNot) eval(a map[string]bool) bool { return !e.inner.eval(a) }
func (e refNot) render() string              { return "not " + wrap(e.inner, 1) }
func (e refNot) prec() int                   { return 1 }

type refAnd struct{ l, r refExpr }

func (e refAnd) eval(a map[string]bool) bool { return e.l.eval(a) && e.r.eval(a) }
func (e refAnd) render() string              { return wrap(e.l, 2) + " and " + wrap(e.r, 2) }
func (e refAnd) prec() int                   { return 2 }

type refOr struct{ l, r refExpr }

func (e refOr) eval(a map[string]bool) bool { return e.l.eval(a) || e.r.eval(a) }
func (e refOr) render() string              { return wrap(e.l, 3) + " or " + wrap(e.r, 3) }
func (e refOr) prec() int                   { return 3 }

// wrap parenthesises a child only when its precedence is looser than the parent's, which is the minimum needed to preserve the
// tree's meaning in text.
func wrap(e refExpr, parent int) string {
	if e.prec() > parent {
		return "(" + e.render() + ")"
	}
	return e.render()
}

func drawExpr(t *rapid.T, depth int) refExpr {
	// Past the depth budget only atoms are drawn, which bounds the tree.
	maxKind := 4
	if depth <= 0 {
		maxKind = 1
	}
	switch rapid.IntRange(0, maxKind).Draw(t, "kind") {
	case 0:
		return refRef{name: rapid.SampledFrom(pbtNames).Draw(t, "name")}
	case 1:
		return refQuant{
			all:    rapid.Bool().Draw(t, "all"),
			prefix: rapid.SampledFrom([]string{"sel_", "flt_", "s"}).Draw(t, "prefix"),
		}
	case 2:
		return refNot{inner: drawExpr(t, depth-1)}
	case 3:
		return refAnd{l: drawExpr(t, depth-1), r: drawExpr(t, depth-1)}
	default:
		return refOr{l: drawExpr(t, depth-1), r: drawExpr(t, depth-1)}
	}
}

// TestCondition_AgreesWithReferenceInterpretation is the property test the issue calls for. It generates a random condition,
// renders it to Sigma text, compiles it through the real parser, and checks that it agrees with an independent evaluation of the
// same tree over a random truth assignment.
//
// This is the right shape for PBT because the input space is the cross-product of expression shapes and truth assignments, which
// no table can enumerate: a precedence or short-circuit bug typically survives every hand-written case and shows up only on a
// particular nesting the author did not think to write.
func TestCondition_AgreesWithReferenceInterpretation(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		expr := drawExpr(t, 3)
		condition := expr.render()

		assign := map[string]bool{}
		for _, n := range pbtNames {
			assign[n] = rapid.Bool().Draw(t, "assign_"+n)
		}

		detection := map[string]any{"condition": condition}
		for _, n := range pbtNames {
			detection[n] = map[string]any{n: "yes"}
		}
		rule, err := Compile(detection)
		require.NoError(t, err, "condition %q must compile", condition)

		ev := mapEvent{}
		for n, on := range assign {
			if on {
				ev[n] = []string{"yes"}
			}
		}

		require.Equal(t, expr.eval(assign), rule.Matches(ev), "condition %q under %v", condition, assign)
	})
}
