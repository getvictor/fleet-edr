//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
)

// spec:observability-instrumentation/per-rule-evaluation-cost-is-recorded-durably/statistics-outlive-the-process-that-produced-them
//
// TestRuleEvalStats_IngestedBatchRecordsPerRuleCost is the only test that crosses the whole path: an agent posts events, the
// processor claims and materializes them, the engine evaluates every dispatched rule, and a row lands in the rules context's
// statistics table.
//
// It exists because every other test for this feature stops at a context boundary. The engine's tests assert what it hands a stub
// recorder; the store's tests assert what it does with a call. Neither touches the two bootstrap accessors or the wiring in
// setup.go that connect them, so all of them stay green if that wiring is deleted, and recording failures are deliberately
// swallowed so nothing would surface at runtime either (issue #833 review).
//
// That gap is not hypothetical. It is exactly how the VARCHAR(64) defect reached a dev server: the unit tests all passed with rule
// ids like "cheap" and "pricey", and the first write against the real catalog failed for all 73 dispatched rules. A test that
// evaluates the REAL catalog, as this one does, would have caught it in CI.
func TestRuleEvalStats_IngestedBatchRecordsPerRuleCost(t *testing.T) {
	t.Parallel()
	stack := Setup(t)

	const hostID = "EEEE1111-2222-3333-4444-555566667777"
	const pid = 7373
	hostToken := stepEnroll(t, stack, hostID)

	now := time.Now().UnixNano()
	postEvents(t, stack, hostToken, []detectionapi.Event{
		{
			EventID: "res-fork", HostID: hostID, TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":1}`, pid)),
		},
		{
			EventID: "res-exec", HostID: hostID, TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(
				`{"pid":%d,"ppid":1,"path":"/usr/bin/true","args":["true"]}`, pid)),
		},
	})
	waitForProcess(t, stack, hostID, pid)

	// Eventually, because the write happens on the processor's drain loop rather than in the ingest request.
	type row struct {
		RuleID      string `db:"rule_id"`
		Evaluations int64  `db:"evaluations"`
		EvalNsSum   int64  `db:"eval_ns_sum"`
		EvalNsMax   int64  `db:"eval_ns_max"`
	}
	var rows []row
	require.Eventually(t, func() bool {
		rows = nil
		if err := stack.DB.SelectContext(t.Context(), &rows,
			`SELECT rule_id, evaluations, eval_ns_sum, eval_ns_max FROM detection_rule_eval_stats`); err != nil {
			return false
		}
		return len(rows) > 0
	}, 5*time.Second, 25*time.Millisecond,
		"an ingested exec batch must leave per-rule statistics: if this is empty the recorder is not wired, which no other test "+
			"would notice because recording failures are swallowed by design")

	longest := 0
	for _, r := range rows {
		assert.Positivef(t, r.Evaluations, "rule %q recorded a row with no attempt", r.RuleID)
		assert.Positivef(t, r.EvalNsSum, "rule %q recorded no time, so the mean it feeds would be zero", r.RuleID)
		assert.GreaterOrEqualf(t, r.EvalNsSum, r.EvalNsMax,
			"rule %q reports a worst case larger than its total, which cannot happen for a single attempt", r.RuleID)
		longest = max(longest, len(r.RuleID))
	}

	// The real catalog, not stub ids, which is the half that would have caught the column-width defect. Asserted as a property of
	// what actually stored rather than against a hardcoded id, so importing a rule with a longer name fails here instead of
	// silently dropping that rule's statistics.
	assert.Greater(t, longest, 64,
		"the catalog ships a rule id longer than the 64 characters every other rule_id column allows, and it has to round-trip "+
			"through this table: if this assertion ever fails, check whether that rule was renamed before relaxing it")
}
