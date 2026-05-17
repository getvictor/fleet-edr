package appcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// Error-message format strings shared by the state-changing service methods. Extracted to constants so Sonar's duplicate-literal
// rule (go:S1192) stays quiet AND wording changes propagate uniformly across CreateRule / UpdateRule / DeleteRule /
// CreatePolicy / UpdatePolicy / DeletePolicy. Each is a fmt.Errorf format string wrapping a sentinel.
const (
	errSvcActorRequiredFmt   = "%w: actor is required"
	errSvcSnapshotComposeFmt = "appcontrol snapshot compose: %w"
)

// CommandInserter is the closure cmd/main supplies so the application-control fan-out can enqueue `set_application_control` commands
// per host. Method-value shape matches response.Service.Insert so cmd/main passes `responseCtx.Service().Insert` directly without an
// adapter.
type CommandInserter func(ctx context.Context, hostID, commandType string, payload []byte) (int64, error)

// HostLister returns the set of host_ids to fan a rule mutation out to. In the demo cut this is every enrolled host in the deployment
// (host-groups + assignments are post-demo); cmd/main passes a thin wrapper over detection.api.Service.ListHosts that projects
// each HostSummary down to its host_id. Distinct closure type rather than reusing detection's so the rules context does not import
// detection outside of the api re-export rule.
type HostLister func(ctx context.Context) ([]string, error)

// Service is the application-control orchestrator the REST handler
// drives. Wraps the persistence layer with the cross-cutting concerns
// every state-changing call has to perform: audit-log emission, and
// fan-out of `set_application_control` commands to every enrolled
// host in the deployment.
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

// ServiceDeps bundles the constructor inputs. Keeps the call site at cmd/main from drifting on argument order when the dep set grows
// (PATCH/DELETE/bulkUpsert will add a couple of audit-action variants post-demo and passing arguments through a struct keeps the
// wiring readable).
type ServiceDeps struct {
	Store    *Store
	Commands CommandInserter
	Hosts    HostLister
	Audit    identityapi.AuditRecorder
	// Clock is optional. Defaults to time.Now. Tests pin a deterministic value so MarshalSetApplicationControlPayload's expires_at filter
	// is predictable across runs.
	Clock  func() time.Time
	Logger *slog.Logger
}

// NewService builds a Service. Store + Commands + Hosts are required; passing nil for any of them is a wiring bug and panics so
// cmd/main surfaces it at boot rather than at the first rule-create. Audit is optional (a nil Audit drops the audit row with a WARN
// log line — the same posture identity's chokepoint uses today on the read-path async fallback).
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

// ListPolicies is the read-only list endpoint's backend. Passes straight through to the store; the orchestrator layer exists so future
// read-side decorators (rule-count aggregation, assignment summary) land in one place without changing the handler.
func (s *Service) ListPolicies(ctx context.Context) ([]api.ApplicationControlPolicy, error) {
	return s.store.ListPolicies(ctx)
}

// GetPolicyWithRules returns the policy row plus its rules in one call so the policy-detail page can render without an extra round
// trip. Returns ErrAppControlPolicyNotFound when the policy is absent; the handler maps that to HTTP 404.
func (s *Service) GetPolicyWithRules(ctx context.Context, policyID int64) (api.ApplicationControlPolicy, error) {
	policies, err := s.store.ListPolicies(ctx)
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
//  1. Validate actor: a nil actor is a wiring bug that would otherwise
//     silently produce an unattributed audit row; we fail closed
//     rather than guess.
//  2. Persist the rule + bump the policy version atomically via
//     store.CreateRule.
//  3. Load the post-bump policy + the full rule list so the snapshot
//     payload reflects current state (the agent sees an INSERT, not a
//     diff). If this step fails, the rule is persisted but unenforced
//     — we emit an audit row marking the compose failure AND return
//     an error so the HTTP layer responds 5xx. The next mutation
//     re-composes from scratch and the rule reaches every host then.
//  4. Marshal a `set_application_control` payload via
//     api.MarshalSetApplicationControlPayload — filters disabled +
//     expired rules per the wire contract.
//  5. Fan out: enqueue one command per enrolled host in the deployment.
//     Per-host failures are accumulated, not aborted; the audit row
//     records fanout_failed for the human triage path. A
//     host-lister failure is distinguished from "no hosts enrolled"
//     by a fanout_skipped_reason key on the audit payload.
//  6. Emit an audit event with fanout_hosts / fanout_failed /
//     fanout_skipped_reason in the payload. The audit row goes out
//     AFTER the fanout so the counts are accurate, and uses sync
//     Record so a crashed audit emit is visible in the response
//     (this is a state-changing call and spec 6.4 makes audit
//     emission part of the contract).
//
// Returns the created rule on success. Validation errors propagate
// untouched so the handler can errors.Is against the
// IsApplicationControlValidationError set.
func (s *Service) CreateRule(
	ctx context.Context,
	req api.CreateRuleRequest,
	actor *identityapi.Actor,
) (api.ApplicationControlRule, error) {
	// Defense in depth: the handler already requires the actor (session middleware pins it before reaching the chokepoint), but failing
	// closed at the service layer means a future caller that bypasses the handler (a CLI tool, a background job) can't silently produce an
	// unattributed audit row.
	if actor == nil {
		return api.ApplicationControlRule{}, fmt.Errorf(errSvcActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}

	rule, err := s.store.CreateRule(ctx, req)
	if err != nil {
		return api.ApplicationControlRule{}, err
	}

	// Compose the post-bump snapshot the agents will receive. Find the parent policy and its full rule list including the just-inserted
	// row.
	policy, payload, err := s.buildSnapshotPayload(ctx, req.PolicyID)
	if err != nil {
		// Rule landed but the snapshot compose failed. Persist the audit signal so the SIEM dashboard can distinguish this
		// state from "rule landed and reached every host", then bubble the error so the HTTP layer returns 5xx. The next
		// mutation re-composes and the rule reaches the hosts then.
		s.emitAudit(ctx, actor, req, rule, 0, 0, 0, "snapshot_compose_failed")
		s.logger.ErrorContext(ctx, "appcontrol: snapshot compose after CreateRule failed; rule is persisted but unenforced until next mutation",
			"err", err, "policy_id", req.PolicyID, "rule_id", rule.ID)
		return api.ApplicationControlRule{}, fmt.Errorf(errSvcSnapshotComposeFmt, err)
	}

	fanoutHosts, fanoutFailed, fanoutSkipReason := s.fanout(ctx, policy.ID, payload)
	s.emitAudit(ctx, actor, req, rule, policy.Version, fanoutHosts, fanoutFailed, fanoutSkipReason)
	return rule, nil
}

// buildSnapshotPayload re-reads the policy + rules after a mutation and renders the wire shape the agent's command codec consumes.
// Separated so the CreateRule path stays linear and the lookup + marshal failure cases have one place to fail.
func (s *Service) buildSnapshotPayload(ctx context.Context, policyID int64) (api.ApplicationControlPolicy, []byte, error) {
	policy, err := s.findPolicyByID(ctx, policyID)
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

// findPolicyByID is the policy lookup the snapshot composer needs. Store doesn't expose a GetPolicyByID (intentionally: the demo cut
// indexes policies by name), so we walk the list. Cheap for the demo's single-policy shape.
func (s *Service) findPolicyByID(ctx context.Context, policyID int64) (api.ApplicationControlPolicy, error) {
	policies, err := s.store.ListPolicies(ctx)
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

// fanoutSkipReason values land verbatim on the audit row when the fan-out couldn't run end-to-end. The empty string means "no skip;
// the loop ran" and is the happy path.
const (
	fanoutSkipReasonHostLister     = "host_lister_error"
	fanoutSkipReasonAssignmentList = "assignment_list_error"
	fanoutSkipReasonNoAssignments  = "no_assignments"
	fanoutSkipReasonNoHosts        = "no_hosts_resolved"
)

// fanout enqueues exactly one set_application_control command per unique host the policy's assigned host groups cover. Phase A's
// only host-group criteria is `{"type":"all"}` (the seed `all-hosts` group) which resolves to every enrolled host via the
// HostLister; Phase B grows the resolver to honor tag / hostname / OS predicates without changing this loop's shape.
//
// Returns (hosts_attempted, hosts_failed, skip_reason). Per-host failures are logged but do NOT abort the loop; the policy is
// already on disk and a missed host will catch up on its next agent poll (the version-monotonic apply in the extension is
// idempotent).
//
// A non-empty skip_reason distinguishes failure modes that would all otherwise audit as fanout_hosts=0:
//   - `host_lister_error`: at least one assigned host group's resolver returned an error (e.g. the HostLister itself failed).
//   - `assignment_list_error`: resolving the policy's assigned host groups failed.
//   - `no_assignments`: the policy has no assigned host groups (a posture admins explicitly choose by detaching all groups; alarming
//     if it happens to the seed Default policy, expected if it happens to a quiescent custom policy).
//   - `no_hosts_resolved`: every assigned host group resolved successfully but to zero hosts (a fresh deployment before any enroll,
//     or a custom group whose criteria currently match nothing — *not* an infra failure).
func (s *Service) fanout(ctx context.Context, policyID int64, payload []byte) (attempted int, failed int, skipReason string) {
	groups, err := s.store.ListHostGroupsForPolicy(ctx, policyID)
	if err != nil {
		s.logger.WarnContext(ctx, "appcontrol: assignment list failed; fan-out skipped", "err", err, "policy_id", policyID)
		return 0, 0, fanoutSkipReasonAssignmentList
	}
	if len(groups) == 0 {
		s.logger.WarnContext(ctx, "appcontrol: policy has no assigned host groups; fan-out skipped", "policy_id", policyID)
		return 0, 0, fanoutSkipReasonNoAssignments
	}

	// Resolve every group's membership to host IDs and union them. Phase A's only criteria is `{"type":"all"}` which delegates to
	// the HostLister; the lookup is memoised per-fanout so a policy with N "all"-criteria groups only enumerates the host list once
	// instead of N times (matters for Phase B custom groups that may also resolve to "all" at the leaf). We track whether ANY
	// group's resolver errored so the audit row distinguishes infra failures from "no hosts enrolled" both when seen is empty AND
	// when seen is partially populated (a partial-failure that drops some hosts would otherwise hide as a successful fan-out).
	seen := make(map[string]struct{})
	hostCache := &allHostsCache{loader: s.hosts}
	var anyResolveErr bool
	for _, g := range groups {
		members, mErr := s.resolveHostGroup(ctx, g, hostCache)
		if mErr != nil {
			anyResolveErr = true
			s.logger.WarnContext(ctx, "appcontrol: host group resolve failed", "err", mErr, "host_group", g.Name)
			continue
		}
		for _, h := range members {
			seen[h] = struct{}{}
		}
	}
	if len(seen) == 0 {
		if anyResolveErr {
			return 0, 0, fanoutSkipReasonHostLister
		}
		return 0, 0, fanoutSkipReasonNoHosts
	}
	for h := range seen {
		attempted++
		if _, err := s.commands(ctx, h, api.CommandTypeSetApplicationControl, payload); err != nil {
			failed++
			s.logger.WarnContext(ctx, "appcontrol: command insert failed", "host_id", h, "err", err)
		}
	}
	// Partial-failure surfacing: even when some hosts were enqueued, signal host_lister_error if any group's resolver failed.
	// Otherwise an operator scanning the audit log sees a "successful" fan-out while one of the policy's assigned groups
	// silently dropped its host set.
	if anyResolveErr {
		return attempted, failed, fanoutSkipReasonHostLister
	}
	return attempted, failed, ""
}

// allHostsCache memoises the HostLister result inside a single fanout call. The loader is invoked at most once per fanout regardless
// of how many host groups carry `{"type":"all"}`; subsequent calls return the cached slice (and any cached error). Zero value is a
// valid cache.
type allHostsCache struct {
	loader func(context.Context) ([]string, error)
	done   bool
	hosts  []string
	err    error
}

func (c *allHostsCache) get(ctx context.Context) ([]string, error) {
	if c.done {
		return c.hosts, c.err
	}
	c.hosts, c.err = c.loader(ctx)
	c.done = true
	return c.hosts, c.err
}

// hostGroupCriteria is the discriminator-only shape the fan-out uses to route to the right resolver. Phase B grows the type set with
// criteria-specific predicate fields; we only need the type tag here.
type hostGroupCriteria struct {
	Type string `json:"type"`
}

// resolveHostGroup parses a host group's criteria JSON and returns the resolved host IDs. Phase A only honors `{"type":"all"}`,
// which delegates to the memoised HostLister (one enumeration per fanout call, no matter how many groups carry the same criteria).
// Phase B adds tag / hostname / OS predicates here without changing the fan-out loop. Unknown / malformed criteria are returned as
// resolver errors so the fanout audit surfaces the misconfiguration as host_lister_error instead of silently dropping the group's
// host set (which would mis-attribute as no_hosts_resolved).
func (s *Service) resolveHostGroup(ctx context.Context, g api.HostGroup, cache *allHostsCache) ([]string, error) {
	var c hostGroupCriteria
	if err := json.Unmarshal(g.Criteria, &c); err != nil {
		return nil, fmt.Errorf("parse criteria for host_group=%q: %w", g.Name, err)
	}
	switch c.Type {
	case api.HostGroupCriteriaTypeAll:
		return cache.get(ctx)
	default:
		return nil, fmt.Errorf("unknown host group criteria type %q for host_group=%q", c.Type, g.Name)
	}
}

// emitAudit records the rule-create event with fanout counts on the
// payload. Sync Record (not Submit) so a state-changing call's audit
// trail is durable — the chokepoint's async path is read-only by
// design. Audit failure is logged but does not bubble up: the rule
// is committed and the fan-out happened; a missing audit row is a
// dashboard gap to investigate, not a 500 for the operator.
//
// policyVersion is the post-bump value when the snapshot composed
// successfully; pass 0 when the compose failed and the version
// isn't reliably knowable. fanoutSkipReason is the empty string on
// the happy path and one of the fanoutSkipReason* constants when
// the audit row needs to record why fanout_hosts is zero. Splitting
// the version + skip-reason out so the failure paths can call this
// with explicit defaults rather than fabricating a fake policy
// struct.
func (s *Service) emitAudit(
	ctx context.Context,
	actor *identityapi.Actor,
	req api.CreateRuleRequest,
	rule api.ApplicationControlRule,
	policyVersion int64,
	fanoutHosts int,
	fanoutFailed int,
	fanoutSkipReason string,
) {
	if s.audit == nil {
		return
	}
	payload := map[string]any{
		"policy_id":      rule.PolicyID,
		"policy_version": policyVersion,
		"rule_type":      string(rule.RuleType),
		"identifier":     rule.Identifier,
		"severity":       string(rule.Severity),
		"reason":         req.Reason,
		"fanout_hosts":   fanoutHosts,
		"fanout_failed":  fanoutFailed,
	}
	if fanoutSkipReason != "" {
		payload["fanout_skipped_reason"] = fanoutSkipReason
	}
	event := identityapi.AuditEvent{
		Action:     identityapi.AuditAppControlRuleCreate,
		TargetType: "application_control_rule",
		TargetID:   strconv.FormatInt(rule.ID, 10),
		ActorEmail: req.Actor,
		Payload:    payload,
	}
	if actor != nil {
		userID := actor.UserID
		event.UserID = &userID
	}
	if err := s.audit.Record(ctx, event); err != nil {
		s.logger.WarnContext(ctx, "appcontrol: audit record failed", "err", err, "rule_id", rule.ID)
	}
}

// recordAudit is the low-level audit emit the per-op helpers share. It centralises the nil-audit guard, the actor-id back-fill,
// and the ActorEmail synthesis so per-op helpers focus on the payload shape rather than the boilerplate.
//
// Actor-id back-fill: when actor is non-nil with a positive UserID, the event's UserID pointer is set so the audit-recorder's
// FK to users lands cleanly. The ActorEmail in the event is preferred when the caller supplied it (matching CreateRule's
// req.Actor pass-through); otherwise a "user:<id>" identifier is synthesised so the event still attributes to a stable subject.
//
// Nil-audit visibility: when s.audit is nil the call drops the row but emits a WARN log per the NewService contract. Security
// mutations otherwise lose their audit signal silently — the operator dashboard would show a normal mutation while the audit log
// has nothing to correlate against, which is the failure mode CodeRabbit flagged on PR #188.
//
// Failed audit emission is logged but not returned; audit is best-effort relative to the mutation that already committed (same
// posture as emitAudit's create-rule path).
func (s *Service) recordAudit(ctx context.Context, actor *identityapi.Actor, evt identityapi.AuditEvent) {
	if actor != nil && actor.UserID > 0 {
		userID := actor.UserID
		evt.UserID = &userID
		if evt.ActorEmail == "" {
			evt.ActorEmail = "user:" + strconv.FormatInt(actor.UserID, 10)
		}
	}
	if s.audit == nil {
		s.logger.WarnContext(ctx, "appcontrol: audit recorder is nil; dropping mutation audit row",
			"action", string(evt.Action), "target_id", evt.TargetID)
		return
	}
	if err := s.audit.Record(ctx, evt); err != nil {
		s.logger.WarnContext(ctx, "appcontrol: audit record failed", "err", err, "target_id", evt.TargetID, "action", string(evt.Action))
	}
}

// UpdateRule wires PATCH /api/v1/app-control/rules/{id}: validates the actor + reason, applies the partial update through the
// store, recomposes the post-update snapshot, fans it out, and emits the application_control.rule_update audit row. Validation
// errors propagate untouched so the handler can errors.Is on the shared IsApplicationControlValidationError set.
func (s *Service) UpdateRule(ctx context.Context, req api.UpdateRuleRequest, actor *identityapi.Actor) (api.ApplicationControlRule, error) {
	if actor == nil {
		return api.ApplicationControlRule{}, fmt.Errorf(errSvcActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	rule, err := s.store.UpdateRule(ctx, req)
	if err != nil {
		return api.ApplicationControlRule{}, err
	}
	policy, payload, composeErr := s.buildSnapshotPayload(ctx, rule.PolicyID)
	if composeErr != nil {
		s.recordRuleMutationAudit(ctx, ruleMutationAuditArgs{
			Action: identityapi.AuditAppControlRuleUpdate, Rule: rule, Actor: actor, ActorString: req.Actor,
			Reason: req.Reason, FanoutSkipReason: "snapshot_compose_failed",
		})
		s.logger.ErrorContext(ctx, "appcontrol: snapshot compose after UpdateRule failed; rule mutation persisted but agents unaware until next mutation",
			"err", composeErr, "policy_id", rule.PolicyID, "rule_id", rule.ID)
		return api.ApplicationControlRule{}, fmt.Errorf(errSvcSnapshotComposeFmt, composeErr)
	}
	fanoutHosts, fanoutFailed, fanoutSkipReason := s.fanout(ctx, policy.ID, payload)
	s.recordRuleMutationAudit(ctx, ruleMutationAuditArgs{
		Action: identityapi.AuditAppControlRuleUpdate, Rule: rule, Actor: actor, ActorString: req.Actor,
		Reason: req.Reason, PolicyVersion: policy.Version,
		FanoutHosts: fanoutHosts, FanoutFailed: fanoutFailed, FanoutSkipReason: fanoutSkipReason,
	})
	return rule, nil
}

// DeleteRule wires DELETE /api/v1/app-control/rules/{id}: looks up the rule (so the audit row records what was removed), deletes
// it, fans out the post-delete snapshot, emits the rule_delete audit. The rule body is captured BEFORE the delete because the
// audit payload references rule_type + identifier; reading after the DELETE would race with the cascade.
func (s *Service) DeleteRule(ctx context.Context, req api.DeleteRuleRequest, actor *identityapi.Actor) error {
	if actor == nil {
		return fmt.Errorf(errSvcActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	priorRule, err := s.store.GetRuleByID(ctx, req.RuleID)
	if err != nil {
		return err
	}
	if _, err := s.store.DeleteRule(ctx, req); err != nil {
		return err
	}
	policy, payload, composeErr := s.buildSnapshotPayload(ctx, priorRule.PolicyID)
	if composeErr != nil {
		s.recordRuleMutationAudit(ctx, ruleMutationAuditArgs{
			Action: identityapi.AuditAppControlRuleDelete, Rule: priorRule, Actor: actor, ActorString: req.Actor,
			Reason: req.Reason, FanoutSkipReason: "snapshot_compose_failed",
		})
		s.logger.ErrorContext(ctx, "appcontrol: snapshot compose after DeleteRule failed; agents still see the deleted rule until next mutation",
			"err", composeErr, "policy_id", priorRule.PolicyID, "rule_id", priorRule.ID)
		return fmt.Errorf(errSvcSnapshotComposeFmt, composeErr)
	}
	fanoutHosts, fanoutFailed, fanoutSkipReason := s.fanout(ctx, policy.ID, payload)
	s.recordRuleMutationAudit(ctx, ruleMutationAuditArgs{
		Action: identityapi.AuditAppControlRuleDelete, Rule: priorRule, Actor: actor, ActorString: req.Actor,
		Reason: req.Reason, PolicyVersion: policy.Version,
		FanoutHosts: fanoutHosts, FanoutFailed: fanoutFailed, FanoutSkipReason: fanoutSkipReason,
	})
	return nil
}

// ruleMutationAuditArgs bundles the per-op inputs recordRuleMutationAudit needs. Struct shape rather than positional params so
// Sonar's S107 (max 7 args) doesn't fire and the four caller sites stay readable. Each field is required; defaults are encoded
// at the call site, not here.
type ruleMutationAuditArgs struct {
	Action           identityapi.AuditAction
	Rule             api.ApplicationControlRule
	Actor            *identityapi.Actor
	ActorString      string // from req.Actor for consistency with CreateRule; recordAudit falls back to "user:<id>" if empty
	Reason           string
	PolicyVersion    int64
	FanoutHosts      int
	FanoutFailed     int
	FanoutSkipReason string
}

// recordRuleMutationAudit is the per-op audit emitter for rule mutations (update + delete). Payload shape matches the create
// flow's so SIEM dashboards can filter on the same key set across all three actions. Takes a struct (S107) so adding new fields
// in Phase B's Detect-mode change (e.g. enforcement_before / enforcement_after) doesn't extend a positional argument list.
func (s *Service) recordRuleMutationAudit(ctx context.Context, args ruleMutationAuditArgs) {
	payload := map[string]any{
		"policy_id":      args.Rule.PolicyID,
		"policy_version": args.PolicyVersion,
		"rule_type":      string(args.Rule.RuleType),
		"identifier":     args.Rule.Identifier,
		"severity":       string(args.Rule.Severity),
		"reason":         args.Reason,
		"fanout_hosts":   args.FanoutHosts,
		"fanout_failed":  args.FanoutFailed,
	}
	if args.FanoutSkipReason != "" {
		payload["fanout_skipped_reason"] = args.FanoutSkipReason
	}
	s.recordAudit(ctx, args.Actor, identityapi.AuditEvent{
		Action:     args.Action,
		TargetType: "application_control_rule",
		TargetID:   strconv.FormatInt(args.Rule.ID, 10),
		ActorEmail: args.ActorString,
		Payload:    payload,
	})
}

// CreatePolicy wires POST /api/v1/app-control/policies. The new policy starts at version=1 with default_action='NONE' and zero
// rules; no fan-out runs because no host group is assigned yet (Phase B exposes the assignments endpoint). The audit row records
// the new policy id + name so an operator can trace the creation back to the request.
func (s *Service) CreatePolicy(ctx context.Context, req api.CreatePolicyRequest, actor *identityapi.Actor) (api.ApplicationControlPolicy, error) {
	if actor == nil {
		return api.ApplicationControlPolicy{}, fmt.Errorf(errSvcActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	policy, err := s.store.CreatePolicy(ctx, req)
	if err != nil {
		return api.ApplicationControlPolicy{}, err
	}
	s.recordPolicyMutationAudit(ctx, actor, req.Actor, identityapi.AuditAppControlPolicyCreate, policy, req.Reason)
	return policy, nil
}

// UpdatePolicy wires PATCH /api/v1/app-control/policies/{id}. Renames + description edits do not change the rules snapshot the
// agents receive, so this path does NOT fan out a new snapshot. The audit row records the post-update version + the actor-supplied
// reason so a future "who renamed Default to corp-default" question has a single source of truth.
func (s *Service) UpdatePolicy(ctx context.Context, req api.UpdatePolicyRequest, actor *identityapi.Actor) (api.ApplicationControlPolicy, error) {
	if actor == nil {
		return api.ApplicationControlPolicy{}, fmt.Errorf(errSvcActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	policy, err := s.store.UpdatePolicy(ctx, req)
	if err != nil {
		return api.ApplicationControlPolicy{}, err
	}
	s.recordPolicyMutationAudit(ctx, actor, req.Actor, identityapi.AuditAppControlPolicyUpdate, policy, req.Reason)
	return policy, nil
}

// DeletePolicy wires DELETE /api/v1/app-control/policies/{id}. Store refuses the seed Default policy (ErrAppControlPolicyImmutable);
// non-Default policies have no assignments in Phase A so no fan-out runs (an admin who attached a custom group + rules in some
// future code path would also need a follow-on snapshot push, but that path does not exist today). The audit captures the
// deleted policy id + name so the deletion is reconstructable from the audit log alone.
func (s *Service) DeletePolicy(ctx context.Context, req api.DeletePolicyRequest, actor *identityapi.Actor) error {
	if actor == nil {
		return fmt.Errorf(errSvcActorRequiredFmt, api.ErrAppControlInvalidRequest)
	}
	priorPolicy, err := s.findPolicyByID(ctx, req.PolicyID)
	if err != nil {
		return err
	}
	if err := s.store.DeletePolicy(ctx, req); err != nil {
		return err
	}
	s.recordPolicyMutationAudit(ctx, actor, req.Actor, identityapi.AuditAppControlPolicyDelete, priorPolicy, req.Reason)
	return nil
}

// recordPolicyMutationAudit is the per-op audit emitter for policy mutations (create + update + delete). Payload mirrors the
// rule-mutation shape modulo fan-out fields (no fan-out on policy mutations in Phase A) so the dashboard query language stays
// consistent across action types. ActorString comes from req.Actor (matching CreateRule's pass-through); recordAudit falls back
// to a synthesised "user:<id>" identifier when actorString is empty so the row still attributes to a stable subject.
func (s *Service) recordPolicyMutationAudit(
	ctx context.Context,
	actor *identityapi.Actor,
	actorString string,
	action identityapi.AuditAction,
	policy api.ApplicationControlPolicy,
	reason string,
) {
	s.recordAudit(ctx, actor, identityapi.AuditEvent{
		Action:     action,
		TargetType: "application_control_policy",
		TargetID:   strconv.FormatInt(policy.ID, 10),
		ActorEmail: actorString,
		Payload: map[string]any{
			"policy_id":      policy.ID,
			"policy_name":    policy.Name,
			"policy_version": policy.Version,
			"reason":         reason,
		},
	})
}
