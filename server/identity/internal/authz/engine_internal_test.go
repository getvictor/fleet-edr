package authz

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
)

// TestAssertActionsParity covers the runtime parity check's failure branches. The happy path (matched sets) is exercised at engine
// construction time by every other test in the package; the missing-from-bundle and missing-from-go paths are not, hence the dedicated
// table here.
func TestAssertActionsParity(t *testing.T) {
	registered := api.RegisteredActions()
	require.NotEmpty(t, registered, "RegisteredActions must be populated")

	bundleAll := make([]any, 0, len(registered))
	for _, a := range registered {
		bundleAll = append(bundleAll, string(a))
	}

	t.Run("matched sets pass", func(t *testing.T) {
		err := assertActionsParity(map[string]any{"actions": bundleAll})
		assert.NoError(t, err)
	})

	t.Run("missing actions key fails fast", func(t *testing.T) {
		err := assertActionsParity(map[string]any{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'actions'")
	})

	t.Run("non-string entry fails", func(t *testing.T) {
		err := assertActionsParity(map[string]any{"actions": []any{string(registered[0]), 42}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-string entry")
	})

	t.Run("missing-from-bundle drift fails with named action", func(t *testing.T) {
		// Drop one action from the bundle copy; the Go side still
		// claims it via RegisteredActions().
		drift := append([]any(nil), bundleAll[1:]...)
		err := assertActionsParity(map[string]any{"actions": drift})
		require.Error(t, err)
		assert.Contains(t, err.Error(), string(registered[0]),
			"error must name the missing-from-bundle action")
	})

	t.Run("missing-from-go drift fails with named action", func(t *testing.T) {
		// Add an action to the bundle that's not in Go's RegisteredActions(). The chokepoint would otherwise grant on actions
		// the Go enum doesn't know about.
		extra := append([]any(nil), bundleAll...)
		extra = append(extra, "ghost.action")
		err := assertActionsParity(map[string]any{"actions": extra})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ghost.action",
			"error must name the missing-from-go action")
	})
}

// TestDecisionFromResultSet covers the result-set decoder's fail-loud paths. The happy path is exercised by every Allow call in
// engine_test.go; the malformed-shape branches need direct invocation because Rego's compiled query never produces them against the
// embedded bundle.
func TestDecisionFromResultSet(t *testing.T) {
	t.Run("empty result set is engine_error", func(t *testing.T) {
		_, err := decisionFromResultSet(rego.ResultSet{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty rego result set")
	})

	t.Run("empty expressions is engine_error", func(t *testing.T) {
		_, err := decisionFromResultSet(rego.ResultSet{rego.Result{}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty rego result set")
	})

	t.Run("non-map decision shape is engine_error", func(t *testing.T) {
		rs := rego.ResultSet{rego.Result{Expressions: []*rego.ExpressionValue{
			{Value: "not a map"},
		}}}
		_, err := decisionFromResultSet(rs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected decision shape")
	})

	t.Run("missing allow field is engine_error", func(t *testing.T) {
		rs := rego.ResultSet{rego.Result{Expressions: []*rego.ExpressionValue{
			{Value: map[string]any{"reason": "granted"}},
		}}}
		_, err := decisionFromResultSet(rs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'allow' field")
	})

	t.Run("missing reason field is engine_error", func(t *testing.T) {
		rs := rego.ResultSet{rego.Result{Expressions: []*rego.ExpressionValue{
			{Value: map[string]any{"allow": true}},
		}}}
		_, err := decisionFromResultSet(rs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'reason' field")
	})

	t.Run("wrong allow type is engine_error", func(t *testing.T) {
		rs := rego.ResultSet{rego.Result{Expressions: []*rego.ExpressionValue{
			{Value: map[string]any{"allow": "yes", "reason": "granted"}},
		}}}
		_, err := decisionFromResultSet(rs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'allow' field")
	})

	t.Run("happy path decodes both fields", func(t *testing.T) {
		rs := rego.ResultSet{rego.Result{Expressions: []*rego.ExpressionValue{
			{Value: map[string]any{"allow": true, "reason": "granted"}},
		}}}
		d, err := decisionFromResultSet(rs)
		require.NoError(t, err)
		assert.True(t, d.Allow)
		assert.Equal(t, "granted", d.Reason)
	})
}

// TestAuditPayload locks the dual-emit shape every audit consumer pivots on: every audit row carries exactly `allow` + `reason` so the
// SigNoz dashboard's grouping queries don't have to handle optional / tri-state fields.
func TestAuditPayload(t *testing.T) {
	cases := []struct {
		name      string
		decision  api.Decision
		wantAllow any
	}{
		{
			name:      "deny",
			decision:  api.Decision{Allow: false, Reason: "no_matching_rule"},
			wantAllow: false,
		},
		{
			name:      "allow",
			decision:  api.Decision{Allow: true, Reason: "granted"},
			wantAllow: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := auditPayload(tc.decision)
			gotKeys := make([]string, 0, len(p))
			for k := range p {
				gotKeys = append(gotKeys, k)
			}
			assert.ElementsMatch(t, []string{"allow", "reason"}, gotKeys)
			assert.Equal(t, tc.wantAllow, p["allow"])
			assert.Equal(t, tc.decision.Reason, p["reason"])
		})
	}
}

// internalAudit is a minimal AuditRecorder used by tests in this package (package authz). The recordingAudit in engine_test.go lives
// in package authz_test and can't be reached from here.
type internalAudit struct{ events []api.AuditEvent }

func (r *internalAudit) Record(_ context.Context, e api.AuditEvent) error {
	r.events = append(r.events, e)
	return nil
}

// TestEngineErrorDecision covers the engine_error helper that both Allow's Eval-failure and decode-failure branches funnel through.
// The two production call sites are otherwise only reachable when OPA itself misbehaves (a paniced PreparedEvalQuery or a malformed
// embedded policy bundle), which is not directly fault-injectable from a test against the real embedded policy. Driving the helper
// directly pins the "deny + reason=engine_error + audit row emitted" invariant the production paths rely on.
func TestEngineErrorDecision(t *testing.T) {
	rec := &internalAudit{}
	e, err := New(t.Context(), rec, nil, Options{})
	require.NoError(t, err)
	actor := &api.Actor{UserID: 1}
	d := e.engineErrorDecision(t.Context(), actor, api.ActionHostIsolate,
		api.Resource{Type: "host", ID: "h1"})
	assert.False(t, d.Allow, "engine_error must deny")
	assert.Equal(t, "engine_error", d.Reason)
	require.Len(t, rec.events, 1, "engine_error must emit exactly one audit row")
	assert.Equal(t, "engine_error", rec.events[0].Payload["reason"])
	assert.Equal(t, false, rec.events[0].Payload["allow"])
}
