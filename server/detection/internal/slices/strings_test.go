package slices

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDeduplicate covers the one behaviour both callers depend on, which is that the ORDER survives.
//
// An alert's event ids are the evidence an analyst reads in the order the events happened, and a finding's techniques are
// rendered in the order the rule declares them. A set that reordered would change what an operator sees for no reason, and it is
// the kind of change nothing else in either path would catch.
func TestDeduplicate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil stays nil", nil, nil},
		{"an empty slice stays empty rather than becoming nil", []string{}, []string{}},
		{"one element needs no work", []string{"a"}, []string{"a"}},
		{"repeats are dropped, first occurrence kept", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"already a set is unchanged", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"order is first-seen, not sorted", []string{"c", "a", "b", "a"}, []string{"c", "a", "b"}},
		{"the empty string is a value like any other", []string{"", "a", ""}, []string{"", "a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.want, Deduplicate(c.in))
		})
	}
}
