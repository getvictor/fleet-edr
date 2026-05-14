package appcontrol

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// CommandInserter is the closure cmd/main supplies so the
// application-control fan-out can enqueue `set_application_control`
// commands per host. Method-value shape matches response.Service.Insert
// so cmd/main passes `responseCtx.Service().Insert` directly without
// an adapter.
type CommandInserter func(ctx context.Context, hostID, commandType string, payload []byte) (int64, error)

// HostLister returns the set of host_ids to fan a rule mutation out
// to. In the demo cut this is every enrolled host in the tenant
// (host-groups + assignments are post-demo); cmd/main passes a thin
// wrapper over detection.api.Service.ListHosts that projects each
// HostSummary down to its host_id. Distinct closure type rather than
// reusing detection's so the rules context does not import detection
// outside of the api re-export rule.
type HostLister func(ctx context.Context) ([]string, error)

// Service is the application-control orchestrator the REST handler
// drives. Wraps the persistence layer with the cross-cutting concerns
// every state-changing call has to perform: audit-log emission, and
// fan-out of `set_application_control` commands to every enrolled
// host in the tenant.
//
// Concurrency: every method is goroutine-safe because Store's
// underlying *sqlx.DB is, and the audit/command closures the
// constructor takes are wired to goroutine-safe services in cmd/main.
type Service struct {
	store    *Store
	commands CommandInserter
	hosts    HostLister
	audit    identityapi.AuditRecorder
	clock    func() time.Time
	logger   *slog.Logger
}

// ServiceDeps bundles the constructor inputs. Keeps the call site at
// cmd/main from drifting on argument order when the dep set grows
// (PATCH/DELETE/bulkUpsert will add a couple of audit-action variants
// post-demo and naming arguments through a struct keeps the wiring
// readable).
type ServiceDeps struct {
	Store    *Store
	Commands CommandInserter
	Hosts    HostLister
	Audit    identityapi.AuditRecorder
	// Clock is optional. Defaults to time.Now. Tests pin a deterministic
	// value so MarshalSetApplicationControlPayload's expires_at filter
	// is predictable across runs.
	Clock  func() time.Time
	Logger *slog.Logger
}

// NewService builds a Service. Store + Commands + Hosts are required;
// passing nil for any of them is a wiring bug and panics so cmd/main
// surfaces it at boot rather than at the first rule-create.
// Audit is optional (a nil Audit drops the audit row with a WARN
// log line — the same posture identity's chokepoint uses today on
// the read-path async fallback).
func NewService(deps ServiceDeps) *Service {
	if deps.Store == nil {
		panic("appcontrol.NewService: Store must not be nil")
	}
	if deps.Commands == nil {
		panic("appcontrol.NewService: Commands must not be nil")
	}
	if deps.Hosts == nil {
		panic("appcontrol.NewService: Hosts must not be nil")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := deps.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		store:    deps.Store,
		commands: deps.Commands,
		hosts:    deps.Hosts,
		audit:    deps.Audit,
		clock:    clock,
		logger:   logger,
	}
}

// ListPolicies is the read-only list endpoint's backend. Passes
// straight through to the store; the orchestrator layer exists so
// future read-side decorators (rule-count aggregation, assignment
// summary) land in one place without changing the handler.
func (s *Service) ListPolicies(ctx context.Context, tenantID string) ([]api.ApplicationControlPolicy, error) {
	return s.store.ListPolicies(ctx, tenantID)
}

// GetPolicyWithRules returns the policy row plus its rules in one
// call so the policy-detail page can render without an extra round
// trip. Returns ErrAppControlPolicyNotFound when the policy is
// absent or owned by a different tenant; the handler maps that to
// HTTP 404. Tenant ownership is enforced here rather than in the
// store so the store stays a thin persistence layer.
func (s *Service) GetPolicyWithRules(ctx context.Context, tenantID string, policyID int64) (api.ApplicationControlPolicy, error) {
	policies, err := s.store.ListPolicies(ctx, tenantID)
	if err != nil {
		return api.ApplicationControlPolicy{}, err
	}
	for _, p := range policies {
		if p.ID == policyID {
			rules, err := s.store.ListRulesByPolicy(ctx, policyID)
			if err != nil {
				return api.ApplicationControlPolicy{}, err
			}
			p.Rules = rules
			return p, nil
		}
	}
	return api.ApplicationControlPolicy{}, api.ErrAppControlPolicyNotFound
}

// CreateRule is the state-changing entry point. Sequence:
//
//  1. Persist the rule + bump the policy version atomically via
//     store.CreateRule.
//  2. Load the post-bump policy + the full rule list so the snapshot
//     payload reflects current state (the agent sees an INSERT, not a
//     diff).
//  3. Marshal a `set_application_control` payload via
//     api.MarshalSetApplicationControlPayload — filters disabled +
//     expired rules per the wire contract.
//  4. Fan out: enqueue one command per enrolled host in the tenant.
//     Failures are accumulated, not aborted; the audit row records
//     fanout_failed for the human triage path.
//  5. Emit an audit event with fanout_hosts / fanout_failed in the
//     payload. The audit row goes out AFTER the fanout so the counts
//     are accurate, and uses sync Record so a crashed audit emit is
//     visible in the response (this is a state-changing call and
//     spec 6.4 makes audit emission part of the contract).
//
// Returns the created rule on success. Validation errors propagate
// untouched so the handler can errors.Is against the
// IsApplicationControlValidationError set.
func (s *Service) CreateRule(ctx context.Context, req api.CreateRuleRequest, actor *identityapi.Actor) (api.ApplicationControlRule, error) {
	rule, err := s.store.CreateRule(ctx, req)
	if err != nil {
		return api.ApplicationControlRule{}, err
	}

	// Compose the post-bump snapshot the agents will receive. Find
	// the parent policy (already in the tenant view) and its full
	// rule list including the just-inserted row.
	policy, payload, err := s.buildSnapshotPayload(ctx, actorTenantID(actor), req.PolicyID)
	if err != nil {
		// Rule landed; the snapshot compose failed. Surface a WARN
		// and skip the fan-out + audit fields that depend on the
		// payload. The next mutation will recompute and re-fan.
		s.logger.WarnContext(ctx, "appcontrol: snapshot compose after CreateRule failed; rule is persisted but fan-out skipped",
			"err", err, "policy_id", req.PolicyID, "rule_id", rule.ID)
		return rule, nil
	}

	fanoutHosts, fanoutFailed := s.fanout(ctx, payload)
	s.emitAudit(ctx, actor, req, rule, policy, fanoutHosts, fanoutFailed)
	return rule, nil
}

// buildSnapshotPayload re-reads the policy + rules after a mutation
// and renders the wire shape the agent's command codec consumes.
// Separated so the CreateRule path stays linear and the lookup +
// marshal failure cases have one place to fail.
func (s *Service) buildSnapshotPayload(ctx context.Context, tenantID string, policyID int64) (api.ApplicationControlPolicy, []byte, error) {
	policy, err := s.findPolicyByID(ctx, tenantID, policyID)
	if err != nil {
		return api.ApplicationControlPolicy{}, nil, err
	}
	rules, err := s.store.ListRulesByPolicy(ctx, policyID)
	if err != nil {
		return api.ApplicationControlPolicy{}, nil, fmt.Errorf("appcontrol list rules for snapshot: %w", err)
	}
	raw, err := api.MarshalSetApplicationControlPayload(policy, rules, s.clock())
	if err != nil {
		return api.ApplicationControlPolicy{}, nil, fmt.Errorf("appcontrol marshal snapshot: %w", err)
	}
	return policy, raw, nil
}

// findPolicyByID is the tenant-scoped policy lookup the snapshot
// composer needs. Store doesn't expose a GetPolicyByID (intentionally:
// the demo cut indexes policies by tenant + name), so we walk the
// tenant list. Cheap for the demo's one-policy-per-tenant shape.
func (s *Service) findPolicyByID(ctx context.Context, tenantID string, policyID int64) (api.ApplicationControlPolicy, error) {
	policies, err := s.store.ListPolicies(ctx, tenantID)
	if err != nil {
		return api.ApplicationControlPolicy{}, err
	}
	for _, p := range policies {
		if p.ID == policyID {
			return p, nil
		}
	}
	return api.ApplicationControlPolicy{}, api.ErrAppControlPolicyNotFound
}

// fanout enqueues exactly one set_application_control command per
// enrolled host in the tenant. Returns (hosts_attempted, hosts_failed)
// for the audit payload. Per-host failures are logged but do NOT
// abort the loop; the policy is already on disk and a missed host
// will catch up on its next agent poll (the version-monotonic apply
// in the extension is idempotent).
func (s *Service) fanout(ctx context.Context, payload []byte) (attempted int, failed int) {
	hosts, err := s.hosts(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "appcontrol: host list failed; fan-out skipped", "err", err)
		return 0, 0
	}
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		attempted++
		if _, err := s.commands(ctx, h, api.CommandTypeSetApplicationControl, payload); err != nil {
			failed++
			s.logger.WarnContext(ctx, "appcontrol: command insert failed", "host_id", h, "err", err)
		}
	}
	return attempted, failed
}

// emitAudit records the rule-create event with fanout counts on the
// payload. Sync Record (not Submit) so a state-changing call's audit
// trail is durable — the chokepoint's async path is read-only by
// design. Audit failure is logged but does not bubble up: the rule
// is committed and the fan-out happened; a missing audit row is a
// dashboard gap to investigate, not a 500 for the operator.
func (s *Service) emitAudit(
	ctx context.Context,
	actor *identityapi.Actor,
	req api.CreateRuleRequest,
	rule api.ApplicationControlRule,
	policy api.ApplicationControlPolicy,
	fanoutHosts int,
	fanoutFailed int,
) {
	if s.audit == nil {
		return
	}
	event := identityapi.AuditEvent{
		Action:     identityapi.AuditAppControlRuleCreate,
		TargetType: "application_control_rule",
		TargetID:   strconv.FormatInt(rule.ID, 10),
		Payload: map[string]any{
			"policy_id":      policy.ID,
			"policy_version": policy.Version,
			"rule_type":      string(rule.RuleType),
			"identifier":     rule.Identifier,
			"severity":       string(rule.Severity),
			"reason":         req.Reason,
			"fanout_hosts":   fanoutHosts,
			"fanout_failed":  fanoutFailed,
		},
	}
	if actor != nil {
		userID := actor.UserID
		event.UserID = &userID
	}
	if err := s.audit.Record(ctx, event); err != nil {
		s.logger.WarnContext(ctx, "appcontrol: audit record failed", "err", err, "rule_id", rule.ID)
	}
}

// actorTenantID returns the tenant the actor is acting on behalf of,
// or "default" if no actor is on the context. Tests that pin actors
// always populate TenantID; the fallback exists so a transient
// middleware regression doesn't make the demo write to the wrong
// tenant's policy.
func actorTenantID(a *identityapi.Actor) string {
	if a == nil || a.TenantID == "" {
		return "default"
	}
	return a.TenantID
}
