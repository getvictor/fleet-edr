package receiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakeSink records the envelopes handed to it so a test can confirm the receive-path tap forwards event bytes to the sink (issue #627).
type fakeSink struct{ got [][]byte }

func (f *fakeSink) ObserveEventBytes(data []byte) { f.got = append(f.got, data) }

// TestGenerationSink_SetAndGet covers the package-level sink seam: it is unset by default, SetGenerationSink installs it, and a nil sink
// is ignored so a stray nil call cannot clear an installed registry.
func TestGenerationSink_SetAndGet(t *testing.T) { //nolint:paralleltest // installs the package-global generation sink; serial
	// SetGenerationSink deliberately ignores nil, so nothing a caller can do puts the package back to holding nothing. The assertion
	// below is about that default state, so it has to start from it and leave it behind: without this the test passes once and fails
	// on every repeat, and `-count` is how an order-dependent failure gets found in the first place.
	prev := getGenerationSink()
	clearGenerationSink()
	t.Cleanup(func() {
		clearGenerationSink()
		SetGenerationSink(prev)
	})

	assert.Nil(t, getGenerationSink(), "no sink is installed by default")

	s := &fakeSink{}
	SetGenerationSink(s)
	got := getGenerationSink()
	if assert.NotNil(t, got) {
		assert.Same(t, s, got.(*fakeSink))
	}

	SetGenerationSink(nil) // nil is ignored; the previously installed sink remains
	got = getGenerationSink()
	if assert.NotNil(t, got) {
		assert.Same(t, s, got.(*fakeSink))
	}
}

// A second implementation of the interface replaces the first rather than crashing. The sink used to be held in an atomic.Value,
// which panics when a later Store hands it a different concrete type, so this is the case that would have taken the agent down.
func TestGenerationSink_AcceptsADifferentImplementation(t *testing.T) { //nolint:paralleltest // package-global sink; serial
	prev := getGenerationSink()
	clearGenerationSink()
	t.Cleanup(func() {
		clearGenerationSink()
		SetGenerationSink(prev)
	})

	first := &fakeSink{}
	SetGenerationSink(first)
	second := &countingSink{}
	SetGenerationSink(second)

	got := getGenerationSink()
	if assert.NotNil(t, got) {
		assert.Same(t, second, got.(*countingSink), "the later sink replaces the earlier one")
	}
}

// countingSink is a second GenerationSink implementation, which is the whole point of it: one concrete type cannot show that the
// package accepts another.
type countingSink struct{ n int }

func (c *countingSink) ObserveEventBytes([]byte) { c.n++ }
