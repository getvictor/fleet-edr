package sigma

import (
	"errors"
	"fmt"
	"strings"
)

// The condition grammar, in the subset the corpus uses:
//
//	condition  := orExpr
//	orExpr     := andExpr ( "or" andExpr )*
//	andExpr    := notExpr ( "and" notExpr )*
//	notExpr    := "not" notExpr | primary
//	primary    := "(" condition ")" | quantifier | identifier
//	quantifier := ( "1" | "all" ) "of" ( glob | "them" )
//
// The six most common condition forms across SigmaHQ's 3,141 rules are `selection` (1,472), `all of selection_*` (482),
// `selection and not 1 of filter_main_*` (191), `selection and not filter` (103), `1 of selection_*` (98), and
// `selection and not 1 of filter_main_* and not 1 of filter_optional_*` (85). Every one is covered above.
//
// Two constructs are deliberately absent because no rule in the corpus uses either: aggregation (`| count(...) by ...`, zero
// rules) and near/timeframe correlation (zero rules). Their absence is the reason this evaluator needs no state between events.
// `them` is implemented despite zero current usage: it is core grammar rather than an edge case, it costs one branch, and #763
// imports upstream rules unmodified, so the corpus we run is not the corpus we measured.

type node interface {
	// eval reports whether the node holds for ev. Searches are evaluated on demand rather than precomputed into a map, so a
	// condition costs nothing to evaluate beyond the searches it actually reaches: `a and not b` never evaluates b when a is
	// false. Conditions reference each search once or twice in practice, so the repeated-reference case is not worth a per-event
	// memo that would allocate on every event of every rule.
	eval(r *Rule, ev Event) bool
}

type refNode struct{ idx int }

func (n refNode) eval(r *Rule, ev Event) bool { return r.searches[n.idx].match(ev) }

type notNode struct{ inner node }

func (n notNode) eval(r *Rule, ev Event) bool { return !n.inner.eval(r, ev) }

type andNode struct{ left, right node }

func (n andNode) eval(r *Rule, ev Event) bool { return n.left.eval(r, ev) && n.right.eval(r, ev) }

type orNode struct{ left, right node }

func (n orNode) eval(r *Rule, ev Event) bool { return n.left.eval(r, ev) || n.right.eval(r, ev) }

// quantNode is `1 of <glob>` or `all of <glob>`. The glob is resolved against the rule's search names at compile time, so
// evaluation walks a fixed index list and the "matches no search" mistake is caught at load.
type quantNode struct {
	all     bool
	indices []int
}

func (n quantNode) eval(r *Rule, ev Event) bool {
	for _, i := range n.indices {
		matched := r.searches[i].match(ev)
		if n.all && !matched {
			return false
		}
		if !n.all && matched {
			return true
		}
	}
	return n.all
}

// tokenize splits a condition into words. The grammar's punctuation is only parentheses, so they are separated from adjacent
// identifiers and everything else splits on whitespace.
func tokenize(s string) []string {
	spaced := strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	return strings.Fields(spaced)
}

// parser is a recursive-descent parser over the token list. It resolves identifiers and globs against searchNames as it goes, so
// a condition naming a search that does not exist fails here rather than evaluating to a silent false forever.
type parser struct {
	tokens []string
	pos    int
	names  []string // search names, in declaration order; index into Rule.searches
}

func (p *parser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *parser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) parseCondition() (node, error) { return p.parseOr() }

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andNode{left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseNot() (node, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.next()
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notNode{inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	tok := p.next()
	switch {
	case tok == "":
		return nil, errors.New("unexpected end of condition")
	case tok == "(":
		inner, err := p.parseCondition()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, errors.New("unclosed parenthesis")
		}
		return inner, nil
	case tok == ")":
		return nil, errors.New("unexpected )")
	case tok == "1" || strings.EqualFold(tok, "all"):
		// Only a quantifier if `of` follows; `all` is otherwise a legal search name.
		if strings.EqualFold(p.peek(), "of") {
			p.next()
			return p.parseQuantifier(strings.EqualFold(tok, "all"))
		}
		return p.reference(tok)
	default:
		return p.reference(tok)
	}
}

func (p *parser) parseQuantifier(all bool) (node, error) {
	pattern := p.next()
	if pattern == "" {
		return nil, errors.New("`of` with no pattern")
	}
	if strings.EqualFold(pattern, "them") {
		pattern = "*"
	}
	var indices []int
	for i, name := range p.names {
		if matchWildcard(name, pattern) {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		// A quantifier matching no search can never fire, so the rule silently detects nothing. That is worth a load failure.
		return nil, fmt.Errorf("`of %s` matches no search identifier", pattern)
	}
	return quantNode{all: all, indices: indices}, nil
}

func (p *parser) reference(name string) (node, error) {
	for i, n := range p.names {
		if n == name {
			return refNode{idx: i}, nil
		}
	}
	return nil, fmt.Errorf("condition references undefined search %q", name)
}
