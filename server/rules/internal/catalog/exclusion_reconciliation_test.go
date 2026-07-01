package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestExclusionMatchTypes_Reconciled is the anti-drift guard for issue #520. It pins, for every registered rule, the exact set of
// exclusion match types the rule declares via SupportedExclusionMatchTypes(). That declared set is the single source of truth the
// create-exclusion API validates against and the admin UI's match-type picker derives from, so this pin makes any change to a rule's
// exclusion surface a visible, reviewed diff rather than silent drift where the UI offers a match type no rule consults.
//
// The companion recording guard (TestExclusionMatchTypes_NoUndeclaredConsultation) proves a rule never QUERIES a match type outside
// its declared set; each rule's own suppression tests prove it actually consults the types it declares.
func TestExclusionMatchTypes_Reconciled(t *testing.T) {
	t.Parallel()

	// expected is the authoritative (rule id -> supported match types) table. A new rule, or a change to a rule's exclusion surface,
	// MUST update this table, which is exactly the reviewable signal we want.
	expected := map[string][]api.ExclusionMatchType{
		"suspicious_exec": {
			api.ExclusionMatchParentPathGlob, api.ExclusionMatchTeamID, api.ExclusionMatchSigningID, api.ExclusionMatchCDHash,
		},
		"persistence_launchagent":       {api.ExclusionMatchPathGlob},
		"sudoers_tamper":                {api.ExclusionMatchPathGlob},
		"privilege_launchd_plist_write": {api.ExclusionMatchTeamID},
		"dyld_insert":                   {},
		"shell_from_office":             {},
		"osascript_network_exec":        {},
		"credential_keychain_dump":      {},
		"application_control_block":     {},
		"dns_c2_beacon":                 {},
	}

	rules := New(nil)
	require.Len(t, rules, len(expected), "expected table must list every registered rule; update it when adding a rule")

	for _, r := range rules {
		t.Run(r.ID(), func(t *testing.T) {
			t.Parallel()
			want, ok := expected[r.ID()]
			require.Truef(t, ok, "rule %q is not in the expected match-type table; add it", r.ID())
			got := r.SupportedExclusionMatchTypes()
			// A rule that consults nothing may return nil or an empty slice; treat them alike. Otherwise order matters: it is the
			// display order the UI offers and the order the API rejection message lists.
			if len(want) == 0 {
				assert.Emptyf(t, got, "rule %q must offer no exclusion match types", r.ID())
			} else {
				assert.Equalf(t, want, got, "rule %q supported match types drifted from the pin", r.ID())
			}
			for _, mt := range got {
				assert.Truef(t, api.IsValidExclusionMatchType(mt), "rule %q declares invalid match type %q", r.ID(), mt)
			}
		})
	}
}

// recordingResolver is an api.ExclusionResolver that records every (ruleID, matchType) pair a rule queries and never excludes, so the
// rule under test fully evaluates and reaches all of its exclusion checks.
type recordingResolver struct {
	queried map[string]map[api.ExclusionMatchType]bool
}

func newRecordingResolver() *recordingResolver {
	return &recordingResolver{queried: map[string]map[api.ExclusionMatchType]bool{}}
}

func (r *recordingResolver) Excluded(ruleID string, matchType api.ExclusionMatchType, _, _ string) bool {
	if r.queried[ruleID] == nil {
		r.queried[ruleID] = map[api.ExclusionMatchType]bool{}
	}
	r.queried[ruleID][matchType] = true
	return false
}

// TestExclusionMatchTypes_NoUndeclaredConsultation drives suspicious_exec (the rule with the richest exclusion surface and the one
// extended in issue #520) through a scenario that reaches every one of its exclusion checks, with a recording resolver, and asserts
// the set of match types it actually queries equals the set it declares. A signed non-shell parent makes the rule consult the path
// glob AND all three signature dimensions, so the recording set is exactly the declared set: no undeclared consultation, no declared
// dead entry.
func TestExclusionMatchTypes_NoUndeclaredConsultation(t *testing.T) {
	t.Parallel()

	s := openCatalogStore(t)
	ctx := t.Context()
	// Signed claude -> /bin/sh -> /tmp/payload: the parent carries code_signing (team_id + signing_id) and a cdhash, so parentExcluded
	// queries all four match types the rule declares.
	events := []api.Event{
		{EventID: "fork-parent", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-parent", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/Applications/Claude.app/Contents/MacOS/claude","args":["claude"],` +
				`"uid":501,"gid":20,"code_signing":{"team_id":"Q6L2SF6YDW","signing_id":"com.anthropic.claude-code","flags":0,` +
				`"is_platform_binary":false},"cdhash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rec := newRecordingResolver()
	rule := &SuspiciousExec{Exclusions: rec}
	_, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)

	declared := map[api.ExclusionMatchType]bool{}
	for _, mt := range rule.SupportedExclusionMatchTypes() {
		declared[mt] = true
	}
	assert.Equal(t, declared, rec.queried["suspicious_exec"],
		"suspicious_exec must query exactly the match types it declares: no undeclared consultation, no dead declaration")
}
