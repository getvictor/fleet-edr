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
