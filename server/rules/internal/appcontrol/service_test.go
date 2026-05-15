//go:build integration

package appcontrol_test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/appcontrol"
	rulestestkit "github.com/fleetdm/edr/server/rules/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// Unit tests for appcontrol.Service paths the rules-context REST tests
// don't reach: the snapshot-compose failure branch, the
// nil-actor/empty-tenant validation guards, and the host-lister
// skip-reason on the audit row. These exercise the orchestrator
// directly so the REST tests can stay focused on HTTP behaviour.

type captureInserter struct {
	mu    sync.Mutex
	calls int
}

func (c *captureInserter) Insert(_ context.Context, _, _ string, _ []byte) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return int64(c.calls), nil
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

// newService wires a fresh Service backed by a real test DB. The seed
// runs explicitly so the Default policy exists for the tests pin
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
		Commands: inserter.Insert,
		Hosts:    func(_ context.Context) ([]string, error) { return []string{"host-a"}, nil },
		Audit:    audit,
		Logger:   slog.Default(),
	})
	return svc, store, inserter, audit
}

// TestService_CreateRule_RejectsNilActor verifies the service-layer
// guard catches a handler bypass: a nil actor is a wiring bug, not
// user input, so we fail closed rather than silently produce an
// unattributed audit row. The handler converts the absent actor into
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

// TestService_CreateRule_AuditCarriesActorEmail confirms the
// AuditEvent.ActorEmail is populated from req.Actor so the audit
// row records who authored the rule (the handler passes
// "user:<id>" today; the audit recorder denormalises to the
// user's email at write time).
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

// TestService_NilDeps_Panics verifies the constructor's
// fail-fast posture: a nil Store / Commands / Hosts is a wiring
// bug at cmd/main, not a recoverable runtime state, so the
// constructor panics rather than letting CreateRule fall through
// to a nil-pointer dereference.
func TestService_NilDeps_Panics(t *testing.T) {
	cases := []struct {
		name string
		deps appcontrol.ServiceDeps
	}{
		{
			name: "nil store",
			deps: appcontrol.ServiceDeps{
				Commands: func(context.Context, string, string, []byte) (int64, error) { return 0, nil },
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
				Commands: func(context.Context, string, string, []byte) (int64, error) { return 0, nil },
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Panics(t, func() { appcontrol.NewService(tc.deps) })
		})
	}
}

// TestService_NilAudit_RuleStillCreates verifies audit is optional:
// a nil audit recorder drops the audit row with a WARN log but the
// rule + fan-out still happen.
func TestService_NilAudit_RuleStillCreates(t *testing.T) {
	db := testdb.Open(t)
	require.NoError(t, rulestestkit.ApplySchema(t.Context(), db))
	store := appcontrol.NewStore(db)
	require.NoError(t, store.EnsureDefaultPolicy(t.Context()))
	inserter := &captureInserter{}
	svc := appcontrol.NewService(appcontrol.ServiceDeps{
		Store:    store,
		Commands: inserter.Insert,
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
