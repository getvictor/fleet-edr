package pipeline

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunner_PropagatesTheMonitorMatchRecorder covers the wiring hop between the detection bootstrap and the processor.
//
// The processor's own tests inject the recorder directly, so nothing exercised the path production actually uses: bootstrap hands
// it to the Runner and the Runner hands it down. Deleting that propagation would leave every processor test green while a real
// deployment emitted the OTel series and persisted nothing, which is the quietest possible way for this feature to not work.
func TestRunner_PropagatesTheMonitorMatchRecorder(t *testing.T) {
	t.Parallel()

	proc := &Processor{}
	r := NewRunner(RunnerOptions{Processor: proc})
	rec := &recordingMonitorRecorder{}

	r.SetMonitorMatchRecorder(rec)

	require.NotNil(t, proc.monitorMatches, "the Runner must hand the recorder to the processor")
	assert.Same(t, rec, proc.monitorMatches)
}

// A Runner without a processor is the ModeIntake shape, where nothing evaluates rules and so nothing has matches to record.
func TestRunner_MonitorMatchRecorderWithoutAProcessor(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() { NewRunner(RunnerOptions{}).SetMonitorMatchRecorder(&recordingMonitorRecorder{}) })
}
