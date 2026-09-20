package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// The operator-visible half of issue #1123. A signature exclusion reads the non-shell parent's persisted code-signing identity, and
// a parent created by fork and never exec'd carried none, so `team_id = <vendor>` suppressed the vendor's exec'd instances and
// alerted on its forked ones. The exclusion looked broken and intermittent, with nothing in the product explaining the difference.
//
// The chain here is the one measured on edr-dev: a signed daemon forks a per-connection worker (sshd forks sshd-session and the
// worker serves the session without exec'ing), the worker spawns a shell, and the shell runs a payload out of /tmp. The worker is
// what the rule names as the chain's non-shell parent, and it is fork-only on exactly the connections that matter.
//
// Nothing in the rule changed. What changed is that the worker's row now carries the daemon's identity, so this is an end-to-end
// assertion over the graph builder and the exclusion matcher together: the events go through the real ProcessBatch.
//
// spec:server-process-graph-builder/a-forked-process-inherits-its-parent-s-signature/an-exclusion-for-a-tool-covers-its-forked-children
func TestSuspiciousExec_ForkOnlyParentIsSuppressedByItsParentsSignature(t *testing.T) {
	t.Parallel()

	const (
		teamID    = "Q6L2SF6YDW"
		signingID = "com.vendor.sshd"
		cdhash    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	signedExec := `,"code_signing":{"team_id":"` + teamID + `","signing_id":"` + signingID +
		`","flags":0,"is_platform_binary":false},"cdhash":"` + cdhash + `"`

	// daemon (50, signed) -> worker (60, forked from it, NEVER exec'd) -> /bin/sh (100) -> /tmp/payload (200).
	events := []detectionapi.Event{
		{EventID: "fork-daemon", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-daemon", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/sbin/sshd","args":["sshd"],"uid":0,"gid":0` + signedExec + `}`)},
		// The worker. No exec event follows it, which is the whole point: it runs its parent's image.
		{EventID: "fork-worker", HostID: "host-a", TimestampNs: 1500, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":60,"parent_pid":50}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":60}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":60,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
	}

	// Baseline first: without it every suppression assertion below could pass because the fixture stopped firing at all.
	t.Run("the chain fires with no exclusion", func(t *testing.T) {
		t.Parallel()
		s := openCatalogStore(t)
		ctx := t.Context()
		require.NoError(t, s.InsertEvents(ctx, events))
		materialize(t, s, events)

		findings, err := (&SuspiciousExec{}).Evaluate(ctx, events, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "the fork-only worker is the chain's non-shell parent and the chain is suspicious")
	})

	// Each dimension of the inherited identity, because all three were NULL on a fork-only row and an operator may have written
	// any of them.
	for _, tc := range []struct {
		name string
		excl fakeExcl
	}{
		{"team_id", fakeExcl{ruleID: "suspicious_exec", matchType: api.ExclusionMatchTeamID, value: teamID}},
		{"signing_id", fakeExcl{ruleID: "suspicious_exec", matchType: api.ExclusionMatchSigningID, value: teamID + ":" + signingID}},
		{"cdhash", fakeExcl{ruleID: "suspicious_exec", matchType: api.ExclusionMatchCDHash, value: cdhash}},
	} {
		t.Run(tc.name+" suppresses a chain whose non-shell parent only ever forked", func(t *testing.T) {
			t.Parallel()
			s := openCatalogStore(t)
			ctx := t.Context()
			require.NoError(t, s.InsertEvents(ctx, events))
			materialize(t, s, events)

			rule := &SuspiciousExec{Exclusions: &fakeExclusions{entries: []fakeExcl{tc.excl}}}
			findings, err := rule.Evaluate(ctx, events, s.GraphReader())
			require.NoError(t, err)
			assert.Empty(t, findings,
				"the worker runs the daemon's binary, so an exclusion for that binary covers it as it covers an exec'd instance")
		})
	}
}

// The fail-safe stays. A worker forked from a parent nothing vouches for inherits nothing, so a signature exclusion must not reach
// it: otherwise inheritance would have turned "we do not know what signed this" into a match.
//
// spec:server-process-graph-builder/a-forked-process-inherits-its-parent-s-signature/a-fork-from-an-unsigned-parent-inherits-nothing
func TestSuspiciousExec_ForkOnlyParentOfAnUnsignedBinaryIsNotSuppressed(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()

	events := []detectionapi.Event{
		{EventID: "fork-daemon", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		// The lookalike: a planted binary at a plausible path, carrying no signature at all.
		{EventID: "exec-daemon", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/tmp/sshd","args":["sshd"],"uid":501,"gid":20}`)},
		{EventID: "fork-worker", HostID: "host-a", TimestampNs: 1500, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":60,"parent_pid":50}`)},
		{EventID: "fork-sh", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":60}`)},
		{EventID: "exec-sh", HostID: "host-a", TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":60,"path":"/bin/sh","args":["sh"],"uid":501,"gid":20}`)},
		{EventID: "fork-payload", HostID: "host-a", TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-payload", HostID: "host-a", TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	rule := &SuspiciousExec{Exclusions: &fakeExclusions{entries: []fakeExcl{
		{ruleID: "suspicious_exec", matchType: api.ExclusionMatchTeamID, value: "Q6L2SF6YDW"},
	}}}
	findings, err := rule.Evaluate(ctx, events, s.GraphReader())
	require.NoError(t, err)
	require.Len(t, findings, 1, "there was no identity to inherit, so the exclusion has nothing to match")
}
