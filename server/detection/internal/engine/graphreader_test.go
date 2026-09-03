package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// stubGraphReader answers every read with the same outcome, so one instance can drive either the failure or the empty-result case.
type stubGraphReader struct {
	err error
}

func (s stubGraphReader) GetProcessByPID(context.Context, string, int, int64) (*api.Process, error) {
	return nil, s.err
}

func (s stubGraphReader) GetProcessByPIDVersion(context.Context, string, int, uint32, int64) (*api.Process, error) {
	return nil, s.err
}

func (s stubGraphReader) GetChildProcesses(context.Context, string, int, api.TimeRange) ([]api.Process, error) {
	return nil, s.err
}

func (s stubGraphReader) GetExecChain(context.Context, api.Process) ([]api.Process, error) {
	return nil, s.err
}

func (s stubGraphReader) GetNetworkEventsForProcess(context.Context, string, int, api.TimeRange) ([]api.Event, error) {
	return nil, s.err
}

func (s stubGraphReader) GetHostEventsByType(context.Context, string, string, api.TimeRange) ([]api.Event, error) {
	return nil, s.err
}

// graphReads is every read a rule can perform, as a callable. Used twice below, once against a failing reader and once against a
// healthy one, so each method is checked for both the wrap and the absence of it.
func graphReads() map[string]func(context.Context, api.GraphReader) error {
	return map[string]func(context.Context, api.GraphReader) error{
		"GetProcessByPID": func(ctx context.Context, gr api.GraphReader) error {
			_, err := gr.GetProcessByPID(ctx, "host", 1, 0)
			return err
		},
		"GetProcessByPIDVersion": func(ctx context.Context, gr api.GraphReader) error {
			_, err := gr.GetProcessByPIDVersion(ctx, "host", 1, 1, 0)
			return err
		},
		"GetChildProcesses": func(ctx context.Context, gr api.GraphReader) error {
			_, err := gr.GetChildProcesses(ctx, "host", 1, api.TimeRange{})
			return err
		},
		"GetExecChain": func(ctx context.Context, gr api.GraphReader) error {
			_, err := gr.GetExecChain(ctx, api.Process{})
			return err
		},
		"GetNetworkEventsForProcess": func(ctx context.Context, gr api.GraphReader) error {
			_, err := gr.GetNetworkEventsForProcess(ctx, "host", 1, api.TimeRange{})
			return err
		},
		"GetHostEventsByType": func(ctx context.Context, gr api.GraphReader) error {
			_, err := gr.GetHostEventsByType(ctx, "host", "exec", api.TimeRange{})
			return err
		},
	}
}

// TestGraphReads_CoversEveryReaderMethod is the table's own guard.
//
// The decorator is protected from interface growth by a compile-time assertion, so a new GraphReader method cannot ship unwrapped.
// The TABLE below has no such protection: a new method would simply go unexercised, and the tests would keep passing while the one
// thing this change promises (that EVERY read failure retries) quietly stopped being covered. Comparing against the interface's
// own method set closes that, and names rather than a count so a rename cannot cancel out an addition.
func TestGraphReads_CoversEveryReaderMethod(t *testing.T) {
	t.Parallel()

	readerType := reflect.TypeFor[api.GraphReader]()
	var declared []string
	for m := range readerType.Methods() {
		declared = append(declared, m.Name)
	}
	var covered []string
	for name := range graphReads() {
		covered = append(covered, name)
	}
	sort.Strings(declared)
	sort.Strings(covered)
	assert.Equal(t, declared, covered,
		"every GraphReader method must appear in the table, or a read failure it can produce goes unchecked")
}

// spec:server-detection-rules-engine/rule-failure-isolation-batch-retry-on-persistence-failure/a-failed-process-graph-read-retries-the-batch-instead-of-acknowledging-it
//
// TestRetryableGraphReader_WrapsEveryReadFailure pins the classification itself: any read that FAILS is retryable.
//
// Per-rule isolation swallows a non-retryable error and the processor then acks, so before this an ordinary database failure cost
// the detections for every event in flight and left a single WARN line behind (issue #798). The sentinel is what separates "this
// rule is wrong" from "this rule's dependency is down", and the two want opposite handling.
func TestRetryableGraphReader_WrapsEveryReadFailure(t *testing.T) {
	t.Parallel()

	readErr := errors.New("dial tcp 127.0.0.1:3306: connect: connection refused")
	reader := &retryableGraphReader{inner: stubGraphReader{err: readErr}}

	for name, read := range graphReads() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := read(t.Context(), reader)
			require.Error(t, err)
			require.ErrorIs(t, err, rulesapi.ErrRetryBatch,
				"a read that could not be answered must fail the batch, not be isolated like a broken rule")
			require.ErrorIs(t, err, readErr, "and must keep the underlying cause, or the log says only that something failed")
			assert.Contains(t, err.Error(), name, "naming the read is what makes the log actionable")
		})
	}
}

// spec:server-detection-rules-engine/rule-failure-isolation-batch-retry-on-persistence-failure/a-read-that-finds-nothing-is-not-a-failure
//
// TestRetryableGraphReader_EmptyResultIsNotAFailure is the other half, and the half that would turn this change into an outage.
//
// An absent row is an ANSWER: most reads here miss most of the time, because most processes are not the parent of an Office
// document or the subject of a keychain dump. Marking those retryable would nack essentially every batch forever.
func TestRetryableGraphReader_EmptyResultIsNotAFailure(t *testing.T) {
	t.Parallel()

	reader := &retryableGraphReader{inner: stubGraphReader{err: nil}}
	for name, read := range graphReads() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, read(t.Context(), reader),
				"a read that matched no row answered the question; only a read that could not answer is retryable")
		})
	}
}

// readingRule performs one graph read and wraps whatever it gets the way the production rules do, with a bare fmt.Errorf and no
// awareness of the retry sentinel. That is the point: no rule has to know.
type readingRule struct {
	stubRule
}

func (r *readingRule) Evaluate(ctx context.Context, _ []api.Event, gr rulesapi.GraphReader) ([]api.Finding, error) {
	if _, err := gr.GetProcessByPID(ctx, "host-a", 42, 0); err != nil {
		return nil, fmt.Errorf("readingRule: resolve pid 42: %w", err)
	}
	return nil, nil
}

// spec:server-detection-rules-engine/rule-failure-isolation-batch-retry-on-persistence-failure/a-failed-process-graph-read-retries-the-batch-instead-of-acknowledging-it
//
// TestEngine_Evaluate_FailedGraphReadFailsTheBatch is the end-to-end half, and the one that matters.
//
// The decorator returning a wrapped error proves nothing on its own: the engine could still swallow it, which is exactly what it
// did before, and a rule wraps the error in its own before the engine ever sees it. This drives the whole path, through a rule
// that knows nothing about the sentinel, and asserts the engine surfaces the failure to the processor rather than logging it and
// letting the batch be acked.
func TestEngine_Evaluate_FailedGraphReadFailsTheBatch(t *testing.T) {
	t.Parallel()

	readErr := errors.New("connection refused")
	e := New(nil, nil)
	e.ruleReader = &retryableGraphReader{inner: stubGraphReader{err: readErr}}
	e.Register(&readingRule{stubRule: stubRule{id: "reading_rule"}})

	_, err := e.Evaluate(t.Context(), []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}})

	require.Error(t, err, "a failed graph read must reach the processor, which nacks; swallowing it acks and loses the events")
	require.ErrorIs(t, err, rulesapi.ErrRetryBatch)
	require.ErrorIs(t, err, readErr, "the cause survives the rule's own wrapping and the engine's")
}

// readerCapturingRule records the reader it was handed and performs NO read, which is what keeps the wiring assertion below from
// depending on what a read does.
type readerCapturingRule struct {
	stubRule
	got rulesapi.GraphReader
}

func (r *readerCapturingRule) Evaluate(_ context.Context, _ []api.Event, gr rulesapi.GraphReader) ([]api.Finding, error) {
	r.got = gr
	return nil, nil
}

// TestEngine_HandsRulesTheRetryableReader pins the wiring on its own, separately from what a failed read then does.
//
// Worth a test of its own because the end-to-end test catches a reverted call site only by accident: the engine's store handle is
// nil in a unit test, so handing rules the bare store panics inside the rule rather than failing an assertion. That is a real
// failure but the wrong one, and it would stop being a failure at all the day this test grows a non-nil store. Capturing the
// reader without reading through it fails for the actual reason instead.
func TestEngine_HandsRulesTheRetryableReader(t *testing.T) {
	t.Parallel()

	e := New(nil, nil)
	rule := &readerCapturingRule{stubRule: stubRule{id: "capturing_rule"}}
	e.Register(rule)

	_, err := e.Evaluate(t.Context(), []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}})
	require.NoError(t, err)

	require.NotNil(t, rule.got, "the rule must have been evaluated, or this asserts nothing")
	assert.IsType(t, &retryableGraphReader{}, rule.got,
		"rules must read through the decorator; handed the bare store, a failed read is isolated and the batch is acked (#798)")
	assert.Same(t, e.ruleReader, rule.got, "and it must be the engine's own instance, not a fresh one built per batch")
}
