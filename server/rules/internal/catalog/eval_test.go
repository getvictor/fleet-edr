package catalog

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/rule-failure-isolation-batch-retry-on-persistence-failure/a-failed-read-stops-that-rule-s-pass-over-the-batch-rather-than-repeating-itself-per-event
//
// TestPendingMiss_AbsorbPropagatesReadFailure pins the amplification bound, which the first cut of #798 removed by accident.
//
// absorb continues the batch past a retryable per-event miss on purpose (issue #661: one permanently orphaned event must not mask
// every other event behind it). A failed graph READ is not that condition. Every remaining read in the batch will fail identically,
// so continuing turns one outage into a read per event per rule, on every retry, for as long as the queue keeps re-offering the
// batch: load on a database that is already in trouble, which delays the recovery the retry is waiting for.
//
// This is what absorb's own comment always claimed ("retrying the remaining events against a broken reader would just multiply the
// failure"). Routing read failures through the generic retry sentinel quietly made the code stop matching it.
func TestPendingMiss_AbsorbPropagatesReadFailure(t *testing.T) {
	t.Parallel()

	t.Run("a failed read is propagated, not absorbed", func(t *testing.T) {
		t.Parallel()
		var p pendingMiss
		readErr := fmt.Errorf("graph read GetExecChain: connection refused: %w", api.ErrRuleReadUnavailable)

		got := p.absorb(readErr)

		require.Error(t, got, "the caller must stop the batch rather than keep reading against a failed dependency")
		require.ErrorIs(t, got, api.ErrRuleReadUnavailable)
		require.NoError(t, p.err, "and it must not be parked as a per-event miss, which is what would continue the loop")
	})

	t.Run("an ordinary retryable miss is still absorbed", func(t *testing.T) {
		t.Parallel()
		var p pendingMiss
		miss := fmt.Errorf("pid 42: %w", api.ErrProcessNotYetMaterialized)

		got := p.absorb(miss)

		require.NoError(t, got, "issue #661: one undecidable event must not mask the rest of the batch")
		require.ErrorIs(t, p.err, api.ErrProcessNotYetMaterialized, "it is remembered and reported after the loop")
	})
}

// spec:server-detection-rules-engine/rule-failure-isolation-batch-retry-on-persistence-failure/a-failed-read-keeps-the-findings-already-resolved
//
// TestEvalEachEvent_KeepsFindingsWhenAReadFails covers what propagating the read failure nearly threw away.
//
// evalEachEvent's contract, stated in its own doc comment, is that it returns the findings it collected ALONGSIDE a retryable
// error: the engine persists them and still retries the batch. Propagating the read failure through the fatal path returned nil
// findings and silently broke that. It matters at exactly the moment the feature is under strain: a batch that keeps failing is
// eventually set aside, and nothing then re-derives the detections the earlier events had already produced, so they are lost
// outright rather than delayed.
//
// A genuinely non-retryable error still discards, because that path means the rule misbehaved and its output is not trustworthy.
func TestEvalEachEvent_KeepsFindingsWhenAReadFails(t *testing.T) {
	t.Parallel()

	events := []api.Event{{EventID: "e1"}, {EventID: "e2"}, {EventID: "e3"}}

	t.Run("a failed read keeps what earlier events resolved", func(t *testing.T) {
		t.Parallel()
		// The first event resolves a finding; the second hits an unavailable dependency.
		findings, err := evalEachEvent(t.Context(), events, nil,
			func(_ context.Context, evt api.Event, _ api.GraphReader) (*api.Finding, error) {
				if evt.EventID == "e1" {
					return &api.Finding{RuleID: "r", Subject: "e1"}, nil
				}
				return nil, fmt.Errorf("rule read GetExecChain: refused: %w", api.ErrRuleReadUnavailable)
			})

		require.ErrorIs(t, err, api.ErrRuleReadUnavailable, "the batch is still failed so the processor retries it")
		require.Len(t, findings, 1, "and the finding e1 already produced survives, for the engine to persist")
		assert.Equal(t, "e1", findings[0].Subject)
	})

	t.Run("a broken rule still discards them", func(t *testing.T) {
		t.Parallel()
		findings, err := evalEachEvent(t.Context(), events, nil,
			func(_ context.Context, evt api.Event, _ api.GraphReader) (*api.Finding, error) {
				if evt.EventID == "e1" {
					return &api.Finding{RuleID: "r", Subject: "e1"}, nil
				}
				return nil, errors.New("nil map write")
			})

		require.Error(t, err)
		require.NotErrorIs(t, err, api.ErrRetryBatch)
		assert.Empty(t, findings, "a rule that misbehaved has untrustworthy output, so the batch's findings are dropped")
	})
}
