//go:build integration

package appcontrol_test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/appcontrol"
	rulestestkit "github.com/fleetdm/edr/server/rules/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// Unit tests for appcontrol.Service paths the rules-context REST tests don't reach: the snapshot-compose failure branch, the
// nil-actor/empty-tenant validation guards, and the host-lister skip-reason on the audit row. These exercise the orchestrator directly
// so the REST tests can stay focused on HTTP behaviour.

// captureInserter is a batch CommandBatchInserter stub. calls counts how many times the fan-out invoked the batch insert (one
// per mutation, not one per host). Returns the chunk's host count as the inserted total so the service computes fanout_failed=0
// on the happy path.
type captureInserter struct {
	mu    sync.Mutex
	calls int
}

func (c *captureInserter) InsertBatch(_ context.Context, hostIDs []string, _ string, _ []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return len(hostIDs), nil
}

type captureAudit struct {
	mu     sync.Mutex
	events []identityapi.AuditEvent
}

func (c *captureAudit) Record(_ context.Context, e identityapi.AuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

func (c *captureAudit) snapshot() []identityapi.AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]identityapi.AuditEvent, len(c.events))
	copy(out, c.events)
	return out
}

func newAdmin() *identityapi.Actor {
	return &identityapi.Actor{UserID: 7}
}

// newService wires a fresh Service backed by a real test DB. The seed runs explicitly so the Default policy exists for the tests pin
// under.
func newService(t *testing.T) (*appcontrol.Service, *appcontrol.Store, *captureInserter, *captureAudit) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, rulestestkit.ApplySchema(t.Context(), db))
	store := appcontrol.NewStore(db)
	require.NoError(t, store.EnsureDefaultPolicy(t.Context()))
	inserter := &captureInserter{}
	audit := &captureAudit{}
	svc := appcontrol.NewService(appcontrol.ServiceDeps{
		Store:    store,
		Commands: inserter.InsertBatch,
		Hosts:    func(_ context.Context) ([]string, error) { return []string{"host-a"}, nil },
		Audit:    audit,
		Logger:   slog.Default(),
	})
	return svc, store, inserter, audit
}

// TestService_CreateRule_RejectsNilActor verifies the service-layer guard catches a handler bypass: a nil actor is a wiring bug,
// not user input, so we fail closed rather than silently produce an unattributed audit row. The handler converts the absent actor into
// a 500 directly; this gate is the back-stop for any non-HTTP caller.
func TestService_CreateRule_RejectsNilActor(t *testing.T) {
	svc, store, _, _ := newService(t)
	policy, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)

	_, err = svc.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("a", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "user:7",
		Reason:     "test",
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlInvalidRequest)
}

// TestService_CreateRule_AuditCarriesActorEmail confirms the AuditEvent.ActorEmail is populated from req.Actor so the audit row
// records who authored the rule (the handler passes "user:<id>" today; the audit recorder denormalises to the user's email at write
// time).
func TestService_CreateRule_AuditCarriesActorEmail(t *testing.T) {
	svc, store, _, audit := newService(t)
	policy, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)

	_, err = svc.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("c", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "admin@audit.test",
		Reason:     "actor email check",
	}, newAdmin())
	require.NoError(t, err)

	events := audit.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, "admin@audit.test", events[0].ActorEmail,
		"AuditEvent must carry req.Actor so the audit row records who authored the rule")
}

// TestService_NilDeps_Panics verifies the constructor's fail-fast posture: a nil Store / Commands / Hosts is a wiring bug at cmd/main,
// not a recoverable runtime state, so the constructor panics rather than letting CreateRule fall through to a nil-pointer dereference.
func TestService_NilDeps_Panics(t *testing.T) {
	cases := []struct {
		name string
		deps appcontrol.ServiceDeps
	}{
		{
			name: "nil store",
			deps: appcontrol.ServiceDeps{
				Commands: func(context.Context, []string, string, []byte) (int, error) { return 0, nil },
				Hosts:    func(context.Context) ([]string, error) { return nil, nil },
			},
		},
		{
			name: "nil commands",
			deps: appcontrol.ServiceDeps{
				Store: &appcontrol.Store{},
				Hosts: func(context.Context) ([]string, error) { return nil, nil },
			},
		},
		{
			name: "nil hosts",
			deps: appcontrol.ServiceDeps{
				Store:    &appcontrol.Store{},
				Commands: func(context.Context, []string, string, []byte) (int, error) { return 0, nil },
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Panics(t, func() { appcontrol.NewService(tc.deps) })
		})
	}
}

// TestService_NilAudit_RuleStillCreates verifies audit is optional: a nil audit recorder drops the audit row with a WARN log but the
// rule + fan-out still happen.
func TestService_NilAudit_RuleStillCreates(t *testing.T) {
	db := testdb.Open(t)
	require.NoError(t, rulestestkit.ApplySchema(t.Context(), db))
	store := appcontrol.NewStore(db)
	require.NoError(t, store.EnsureDefaultPolicy(t.Context()))
	inserter := &captureInserter{}
	svc := appcontrol.NewService(appcontrol.ServiceDeps{
		Store:    store,
		Commands: inserter.InsertBatch,
		Hosts:    func(_ context.Context) ([]string, error) { return []string{"host-a"}, nil },
		Logger:   slog.Default(),
	})
	policy, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)

	rule, err := svc.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("d", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "user:7",
		Reason:     "nil audit",
	}, newAdmin())
	require.NoError(t, err)
	assert.NotZero(t, rule.ID)
	assert.Equal(t, 1, inserter.calls, "fan-out runs even without audit")
}

// fanoutAuditPayloadFor returns the most recent rule_create audit row's payload, or fails the test if none has been recorded. Used
// by the fanout skip-reason tests below to pin the operator-visible diagnostic.
func fanoutAuditPayloadFor(t *testing.T, audit *captureAudit) map[string]any {
	t.Helper()
	events := audit.snapshot()
	require.NotEmpty(t, events, "expected at least one audit event")
	return events[len(events)-1].Payload
}

// detachDefaultAssignment removes the Default-policy -> all-hosts assignment so the fanout audits as no_assignments rather than
// fanning out to every enrolled host. Used by tests that pin the skip-reason for that specific posture.
func detachDefaultAssignment(t *testing.T, db *sqlx.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), "DELETE FROM app_control_assignments WHERE policy_id = (SELECT id FROM app_control_policies WHERE name = ?)", api.DefaultPolicyName)
	require.NoError(t, err)
}

// attachHostGroup creates a host group with the given criteria JSON and assigns it to the Default policy. Returns the new group's
// id so the caller can re-detach it if needed. Inserts directly because the public Store has no Create/Assign API in Phase A.
func attachHostGroup(t *testing.T, db *sqlx.DB, name string, criteria string) int64 {
	t.Helper()
	ctx := t.Context()
	res, err := db.ExecContext(ctx, "INSERT INTO host_groups (name, description, criteria) VALUES (?, ?, ?)", name, "phase-a test", criteria)
	require.NoError(t, err)
	gID, err := res.LastInsertId()
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO app_control_assignments (policy_id, host_group_id, priority) SELECT id, ?, 0 FROM app_control_policies WHERE name = ?", gID, api.DefaultPolicyName)
	require.NoError(t, err)
	return gID
}

// newServiceWithHostsAndAudit is a small variation on newService that lets the caller plug in a custom HostLister + lets the caller
// observe the audit recorder. Returned for the fanout skip-reason tests below.
func newServiceWithHostsAndAudit(t *testing.T, hosts func(context.Context) ([]string, error)) (*appcontrol.Service, *appcontrol.Store, *sqlx.DB, *captureAudit) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, rulestestkit.ApplySchema(t.Context(), db))
	store := appcontrol.NewStore(db)
	require.NoError(t, store.EnsureDefaultPolicy(t.Context()))
	inserter := &captureInserter{}
	audit := &captureAudit{}
	svc := appcontrol.NewService(appcontrol.ServiceDeps{
		Store:    store,
		Commands: inserter.InsertBatch,
		Hosts:    hosts,
		Audit:    audit,
		Logger:   slog.Default(),
	})
	return svc, store, db, audit
}

// TestService_Fanout_NoAssignments pins the audit row when the policy has no assigned host groups: skip_reason is "no_assignments"
// and the rule still persists (the rule body is on disk; only the fan-out is skipped).
func TestService_Fanout_NoAssignments(t *testing.T) {
	svc, store, db, audit := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) {
		t.Fatal("HostLister must not be called when there are no assignments")
		return nil, nil
	})
	detachDefaultAssignment(t, db)
	policy, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)

	rule, err := svc.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("a", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "user:7",
		Reason:     "fanout: no_assignments",
	}, newAdmin())
	require.NoError(t, err)
	assert.NotZero(t, rule.ID)

	payload := fanoutAuditPayloadFor(t, audit)
	assert.Equal(t, "no_assignments", payload["fanout_skipped_reason"], "policy without assignments must audit as no_assignments")
	assert.Equal(t, 0, payload["fanout_hosts"])
}

// TestService_Fanout_NoHostsResolved pins the audit row when every assigned group resolves successfully but to zero hosts. This is
// the fresh-deployment posture: the HostLister has no errors, just no hosts enrolled yet. The previous demo cut mislabelled this as
// host_lister_error which mis-paged operators on first deploy.
func TestService_Fanout_NoHostsResolved(t *testing.T) {
	svc, store, _, audit := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) {
		return []string{}, nil // empty, no error
	})
	policy, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)

	_, err = svc.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("b", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "user:7",
		Reason:     "fanout: no_hosts_resolved",
	}, newAdmin())
	require.NoError(t, err)

	payload := fanoutAuditPayloadFor(t, audit)
	assert.Equal(t, "no_hosts_resolved", payload["fanout_skipped_reason"], "empty HostLister result must audit as no_hosts_resolved, not host_lister_error")
	assert.Equal(t, 0, payload["fanout_hosts"])
}

// TestService_Fanout_HostListerError covers the resolver-error path: a host group whose criteria type is unknown returns an error
// from resolveHostGroup, which surfaces as host_lister_error in the audit row. This is also the only Phase A path that exercises
// the "unknown criteria" error branch: Phase B's tag/hostname/OS resolvers don't exist yet.
func TestService_Fanout_HostListerError(t *testing.T) {
	svc, store, db, audit := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) {
		t.Fatal("HostLister must not be called when criteria is unknown")
		return nil, nil
	})
	detachDefaultAssignment(t, db)
	attachHostGroup(t, db, "phase-b-criteria", `{"type":"unknown"}`)
	policy, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)

	_, err = svc.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("c", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "user:7",
		Reason:     "fanout: host_lister_error via unknown criteria",
	}, newAdmin())
	require.NoError(t, err)

	payload := fanoutAuditPayloadFor(t, audit)
	assert.Equal(t, "host_lister_error", payload["fanout_skipped_reason"], "unknown criteria must surface as host_lister_error")
	assert.Equal(t, 0, payload["fanout_hosts"])
}

// TestService_Fanout_CachesHostLister pins the allHostsCache memoisation: when a policy has multiple assigned host groups all
// resolving to {"type":"all"}, the HostLister is invoked exactly once per fanout call (not N times). Matters for Phase B policies
// with overlapping groups that all leaf-resolve to "all".
func TestService_Fanout_CachesHostLister(t *testing.T) {
	var calls int
	svc, store, db, audit := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) {
		calls++
		return []string{"host-a", "host-b"}, nil
	})
	// Default policy already has the seeded all-hosts group; add a second all-hosts-2 group so the loop walks twice.
	attachHostGroup(t, db, "all-hosts-2", `{"type":"all"}`)
	policy, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)

	_, err = svc.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("e", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "user:7",
		Reason:     "fanout: hostLister cache",
	}, newAdmin())
	require.NoError(t, err)

	assert.Equal(t, 1, calls, "HostLister must be memoised across {\"type\":\"all\"} groups within a single fanout call")
	payload := fanoutAuditPayloadFor(t, audit)
	assert.EqualValues(t, 2, payload["fanout_hosts"], "union of host-a + host-b must dedupe across both all-criteria groups")
}

// TestService_Fanout_PartialFailureAuditsHostListerError covers the partial-failure semantic: one group resolves to a hosts list,
// another's criteria errors. Even though some hosts were enqueued, the audit row carries host_lister_error so operators see the
// partial coverage instead of a silent "successful" fanout.
func TestService_Fanout_PartialFailureAuditsHostListerError(t *testing.T) {
	svc, store, db, audit := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) {
		return []string{"host-a"}, nil
	})
	attachHostGroup(t, db, "phase-b-broken", `{"type":"unknown"}`)
	policy, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)

	_, err = svc.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("f", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "user:7",
		Reason:     "fanout: partial failure surfaces host_lister_error",
	}, newAdmin())
	require.NoError(t, err)

	payload := fanoutAuditPayloadFor(t, audit)
	assert.Equal(t, "host_lister_error", payload["fanout_skipped_reason"], "any resolver error must surface even when some hosts succeed")
	assert.EqualValues(t, 1, payload["fanout_hosts"], "successful group's hosts still get enqueued")
}

// TestService_UpdateRule_FansOutAndAudits pins the PATCH path's contract: the post-update snapshot reaches every assigned host
// (the seeded all-hosts group) and the audit row records rule_update with the post-bump policy version + fanout counts.
func TestService_UpdateRule_FansOutAndAudits(t *testing.T) {
	svc, store, _, audit := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) {
		return []string{"host-a", "host-b"}, nil
	})
	ctx := t.Context()
	policy, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	rule, err := svc.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("1", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "user:7",
		Reason:     "fixture for update",
	}, newAdmin())
	require.NoError(t, err)
	versionAfterCreate := policy.Version + 1 // CreateRule bumps once

	enabled := false
	updated, err := svc.UpdateRule(ctx, api.UpdateRuleRequest{
		RuleID:  rule.ID,
		Enabled: &enabled,
		Actor:   "user:7",
		Reason:  "disable rule",
	}, newAdmin())
	require.NoError(t, err)
	assert.False(t, updated.Enabled)

	payload := fanoutAuditPayloadFor(t, audit)
	assert.EqualValues(t, versionAfterCreate+1, payload["policy_version"], "PATCH must bump version again")
	assert.EqualValues(t, 2, payload["fanout_hosts"], "snapshot fans out to all hosts on update")
}

// TestService_DeleteRule_FansOutAndAudits pins the DELETE path: the rule is gone, the post-delete snapshot reaches every host so
// agents drop the now-missing rule on their next apply, and the audit row captures the prior rule's type/identifier so the SIEM
// query "what rule was deleted at <timestamp>" has a single source of truth.
func TestService_DeleteRule_FansOutAndAudits(t *testing.T) {
	svc, store, _, audit := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) {
		return []string{"host-a"}, nil
	})
	ctx := t.Context()
	policy, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	rule, err := svc.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   policy.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("2", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "user:7",
		Reason:     "fixture for delete",
	}, newAdmin())
	require.NoError(t, err)
	versionAfterCreate := policy.Version + 1

	require.NoError(t, svc.DeleteRule(ctx, api.DeleteRuleRequest{
		RuleID: rule.ID, Actor: "user:7", Reason: "remove after triage",
	}, newAdmin()))

	payload := fanoutAuditPayloadFor(t, audit)
	assert.EqualValues(t, versionAfterCreate+1, payload["policy_version"], "DELETE must bump version")
	assert.Equal(t, "BINARY", payload["rule_type"], "audit captures the prior rule type")
	assert.Equal(t, strings.Repeat("2", 64), payload["identifier"], "audit captures the prior rule identifier")
	assert.EqualValues(t, 1, payload["fanout_hosts"], "post-delete snapshot fans out so agents drop the removed rule")
}

// TestService_CreatePolicy_AuditsAndDoesNotFanOut confirms POST /policies records the audit with policy_create action AND that
// no fanout runs (no rules yet, no hosts to push to). Distinct from the rule paths so the SIEM dashboard can filter "policy
// scoped audit" cleanly.
func TestService_CreatePolicy_AuditsAndDoesNotFanOut(t *testing.T) {
	hostListerCalls := 0
	svc, _, _, audit := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) {
		hostListerCalls++
		return []string{"host-a"}, nil
	})
	policy, err := svc.CreatePolicy(t.Context(), api.CreatePolicyRequest{
		Name: "new-policy", Description: "test", Actor: "user:7", Reason: "create",
	}, newAdmin())
	require.NoError(t, err)
	assert.NotZero(t, policy.ID)
	assert.Equal(t, 0, hostListerCalls, "POST /policies must not fan out (no rules, no assignments)")

	events := audit.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, identityapi.AuditAppControlPolicyCreate, events[0].Action)
	assert.Equal(t, "application_control_policy", events[0].TargetType)
}
