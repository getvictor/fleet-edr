package authz

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/audit"
)

// policyFS bakes the Rego module + JSON data files into the binary.
// Hot-swap of policy bytes is a wave-3 control-plane feature; for
// wave 1 the bundle is a build-time artifact that ships with the
// server binary.
//
//go:embed policy/edr.rego policy/data/actions.json policy/data/roles.json
var policyFS embed.FS

// regoQueryName is the canonical query Engine evaluates. The string is shared with the Rego module's package declaration; renaming
// one without the other is a compile-time silent break (the policy is still valid Rego, but the query yields no results), so the
// constructor checks both ends agree.
const regoQueryName = "data.edr.authz.decision"

// actionAttrKey is the slog / OTel attribute key for the privileged action being evaluated. Callers structure their log entries around
// it so a SigNoz dashboard can pivot on `edr.authz.action` directly.
const actionAttrKey = "edr.authz.action"

// Engine is the AuthZ-interface implementation. Holds the prepared Rego query (compiled at construction time so per-request evaluation
// is the warm path) and the audit recorder every decision flows through.
type Engine struct {
	query rego.PreparedEvalQuery
	audit api.AuditRecorder
	// asyncRead is the optional read-action allow-event path: the chokepoint Submits to it instead of calling audit.Record synchronously
	// when (a) the action is a read action, (b) the decision is Allow, (c) the actor is non-break-glass, and (d) the action is not
	// audit.read (which keeps the audit-of-audit row regardless of sampling). Nil-safe: a missing async writer degrades silently to the
	// synchronous Record path.
	asyncRead api.AsyncAuditWriter
	// readSamplingRate is the inclusion probability (0.0-1.0) for non-carve-out read-allow events. 0.0 (default) emits zero such rows;
	// 1.0 emits every row.
	readSamplingRate float64
	logger           *slog.Logger

	// registered is the action allowlist the chokepoint validates against before invoking Rego. A request that names an unregistered
	// action is denied with reason `action_not_registered`; the build-time parity check between api.RegisteredActions and
	// policy/data/actions.json keeps the two in lockstep, this set is the runtime defense in depth.
	registered map[api.Action]struct{}

	// roleGrants is the role-id -> grant-list map parsed from policy/data/roles.json, the same bundle the Rego store reads. It backs
	// PermissionsForRoleIDs, which the session probe uses to tell the UI which actions an operator's roles confer. It is presentation
	// data only; Allow remains the single authorization decision.
	roleGrants map[string][]string
}

// Options bundles the optional async-audit dependencies. Zero values are valid: a nil AsyncRead degrades to fully-synchronous audit;
// ReadSamplingRate=0 means "audit zero non-carve-out read-allow events" (the wave-1 default).
type Options struct {
	AsyncRead        api.AsyncAuditWriter
	ReadSamplingRate float64
}

// New compiles the embedded Rego policy + bundle data and returns a
// ready-to-use Engine. Audit may be nil only in tests; production
// callers must wire identityCtx.AuditRecorder() so every decision
// lands in audit_events.
//
// ctx is used for the OPA PrepareForEval call only; the engine's
// later Allow calls take their own ctx.
//
// opts carries the async-audit + read-sampling configuration. Zero
// value is valid (no async writer, 0.0 read sampling); production
// wires identityCtx's AsyncWriter, and the read-sampling rate is fixed at 0.0.
func New(ctx context.Context, audit api.AuditRecorder, logger *slog.Logger, opts Options) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	regoBytes, err := fs.ReadFile(policyFS, "policy/edr.rego")
	if err != nil {
		return nil, fmt.Errorf("authz: read embedded rego: %w", err)
	}
	dataObj, err := loadDataBundle()
	if err != nil {
		return nil, err
	}
	if err := assertActionsParity(dataObj); err != nil {
		return nil, err
	}

	store := inmem.NewFromObject(dataObj)
	query, err := rego.New(
		rego.Query(regoQueryName),
		rego.Module("edr.rego", string(regoBytes)),
		rego.Store(store),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("authz: prepare opa query: %w", err)
	}

	registered := make(map[api.Action]struct{}, len(api.RegisteredActions()))
	for _, a := range api.RegisteredActions() {
		registered[a] = struct{}{}
	}

	roleGrants, err := parseRoleGrants()
	if err != nil {
		return nil, err
	}

	e := &Engine{
		query:            query,
		audit:            audit,
		asyncRead:        opts.AsyncRead,
		readSamplingRate: opts.ReadSamplingRate,
		logger:           logger,
		registered:       registered,
		roleGrants:       roleGrants,
	}
	return e, nil
}

// PermissionsForRoleIDs returns the union of action grants conferred by the given role ids, with the `*` wildcard (held by
// super_admin) expanded to the concrete registered action set. The result is deduplicated and sorted for a stable wire shape.
// Unknown role ids are ignored. Scope is the caller's concern: wave-1 passes only deployment-wide (`global`) bindings, matching the
// only scope the chokepoint honours.
//
// This is presentation data for the session probe: it tells the UI which affordances an operator's roles confer so it can hide the
// rest. It is NEVER an authorization decision: every privileged action still funnels through Allow, which is the sole security
// boundary (a stale or wrong permission set can only change what the UI shows, not what the server permits).
func (e *Engine) PermissionsForRoleIDs(roleIDs []string) []string {
	if e == nil {
		// Defensive: a typed-nil *Engine wrapped in the PermissionResolver interface would otherwise panic on the
		// e.roleGrants access below. The session handler treats a nil result as an empty permission set.
		return nil
	}
	seen := make(map[string]struct{})
	for _, id := range roleIDs {
		grants, ok := e.roleGrants[id]
		if !ok {
			continue
		}
		for _, g := range grants {
			if g == "*" {
				for _, a := range api.RegisteredActions() {
					seen[string(a)] = struct{}{}
				}
				continue
			}
			seen[g] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Allow evaluates the policy and returns the decision. Implements
// api.AuthZ. Every decision (allow or deny) is recorded via the
// AuditRecorder when one was provided at construction.
//
// Path order:
//  1. Validate the action against the registered set; reject unknown
//     actions with `action_not_registered` (defense in depth).
//  2. Pull the actor from ctx; reject anonymous calls with `no_actor`.
//  3. Evaluate the Rego query.
//  4. Record the decision via the audit recorder.
func (e *Engine) Allow(ctx context.Context, action api.Action, resource api.Resource) (api.Decision, error) {
	if _, ok := e.registered[action]; !ok {
		d := api.Decision{Allow: false, Reason: "action_not_registered"}
		e.recordDecision(ctx, nil, action, resource, d)
		return d, nil
	}

	actor, ok := api.ActorFromContext(ctx)
	if !ok {
		d := api.Decision{Allow: false, Reason: "no_actor"}
		e.recordDecision(ctx, nil, action, resource, d)
		return d, nil
	}

	input := map[string]any{
		"actor":    actor,
		"action":   string(action),
		"resource": resource,
	}
	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		e.logger.ErrorContext(ctx, "authz evaluate",
			"err", err,
			actionAttrKey, string(action),
			"edr.authz.resource_type", resource.Type)
		return e.engineErrorDecision(ctx, actor, action, resource), fmt.Errorf("%w: %w", api.ErrAuthZUnavailable, err)
	}

	policyDecision, err := decisionFromResultSet(rs)
	if err != nil {
		e.logger.ErrorContext(ctx, "authz decode decision",
			"err", err,
			actionAttrKey, string(action))
		return e.engineErrorDecision(ctx, actor, action, resource), fmt.Errorf("%w: %w", api.ErrAuthZUnavailable, err)
	}

	e.recordDecision(ctx, actor, action, resource, policyDecision)
	return policyDecision, nil
}

// engineErrorDecision builds the canonical engine_error deny, writes the audit row, and returns the decision. Shared by the
// Eval-failure and decode-failure branches in Allow so a single line of code represents both engine-internal-bug paths; the caller
// still wraps the underlying error into the returned error value.
func (e *Engine) engineErrorDecision(ctx context.Context, actor *api.Actor, action api.Action, resource api.Resource) api.Decision {
	d := api.Decision{Allow: false, Reason: "engine_error"}
	e.recordDecision(ctx, actor, action, resource, d)
	return d
}

// recordDecision writes the audit row for this Allow call. Failures
// are logged at WARN, never propagated: an audit-write failure must
// not turn into a permission deny (the spec's audit-of-audit pattern
// is explicit on this: we want both signals when both fail, not a
// false negative cascading from one).
//
// Async-read hybrid path: when the decision is an allow on a non-audit
// read action by a non-break-glass actor, the chokepoint consults
// the read-sampling rate; included events go to the async writer
// (when configured) so the privileged-route hot path doesn't wait on
// an INSERT. Everything else (denies, errors, writes, auth outcomes,
// audit.read, break-glass) remains on the synchronous path so the
// durability invariant on security-relevant signals is preserved.
func (e *Engine) recordDecision(
	ctx context.Context,
	actor *api.Actor,
	action api.Action,
	resource api.Resource,
	d api.Decision,
) {
	if e.audit == nil {
		return
	}
	event := api.AuditEvent{
		Action:     api.AuditAction("authz." + string(action)),
		TargetType: resource.Type,
		TargetID:   resource.ID,
		Payload:    auditPayload(d),
		// Capture trace_id at decision time. The async path runs the eventual INSERT under a background ctx (so a
		// request-scope cancellation doesn't break in-flight audits); without an explicit TraceID the row would land with
		// NULL trace_id and lose correlation. Sync callers can leave the field empty and Store.Record falls back to the
		// ctx-extracted id.
		TraceID: traceIDFromContext(ctx),
	}
	// Only stamp a user id for a real human user. A service-account actor (issue #376) has UserID==0 and no users row; setting it would
	// persist actor_user_id=0 and make the audit writer's actor_email resolution query users for id 0 on every audited call.
	if actor != nil && actor.UserID > 0 {
		uid := actor.UserID
		event.UserID = &uid
	}
	if e.routeAsync(action, d, actor) {
		if !audit.ShouldSampleRead(action, false, e.readSamplingRate) {
			return
		}
		if e.asyncRead.Submit(ctx, event) {
			return
		}
		// Submit returned false (queue full or writer stopped); fall through to the sync path so the row still lands.
		// The async writer already logged the queue-full WARN; double-logging the same event is acceptable to keep the audit
		// record.
	}
	if err := e.audit.Record(ctx, event); err != nil {
		e.logger.WarnContext(ctx, "authz audit write",
			"err", err,
			actionAttrKey, string(action),
			"edr.authz.allow", d.Allow,
			"edr.authz.reason", d.Reason)
	}
}

// routeAsync reports whether this (action, decision, actor) tuple is a candidate for the async + sampling path. Returns true only
// when every guard holds: an allow decision, a non-audit-read action that IS a read action, a non-break-glass actor, and an asyncRead
// writer configured. Any miss falls through to the sync path so security-relevant signals are never sampled out.
func (e *Engine) routeAsync(action api.Action, d api.Decision, actor *api.Actor) bool {
	if e.asyncRead == nil {
		return false
	}
	if !d.Allow {
		return false
	}
	if actor == nil || actor.IsBreakglass {
		return false
	}
	if action == api.ActionAuditRead {
		return false
	}
	return api.IsReadAction(action)
}

// traceIDFromContext extracts the active OTel trace id at chokepoint time so the chokepoint can pin it on the AuditEvent before
// submitting. Mirrors the audit package's private helper; arch-go forbids reaching across into another context's internal package,
// so the chokepoint owns its own copy. Empty when no span is active.
func traceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

func auditPayload(d api.Decision) map[string]any {
	return map[string]any{
		"allow":  d.Allow,
		"reason": d.Reason,
	}
}

// loadDataBundle reads the embedded JSON bundles and returns the
// merged object the OPA store consumes. The shape is:
//
//	{
//	  "actions": [...],   // mirrored from api.RegisteredActions
//	  "roles": {<id>: {"grants": [...]}, ...}
//	}
func loadDataBundle() (map[string]any, error) {
	actionsBytes, err := fs.ReadFile(policyFS, "policy/data/actions.json")
	if err != nil {
		return nil, fmt.Errorf("authz: read actions.json: %w", err)
	}
	rolesBytes, err := fs.ReadFile(policyFS, "policy/data/roles.json")
	if err != nil {
		return nil, fmt.Errorf("authz: read roles.json: %w", err)
	}
	var actions struct {
		Actions []string `json:"actions"`
	}
	if err := json.Unmarshal(actionsBytes, &actions); err != nil {
		return nil, fmt.Errorf("authz: parse actions.json: %w", err)
	}
	var roles struct {
		Roles map[string]struct {
			Grants []string `json:"grants"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(rolesBytes, &roles); err != nil {
		return nil, fmt.Errorf("authz: parse roles.json: %w", err)
	}
	rolesData := make(map[string]any, len(roles.Roles))
	for id, r := range roles.Roles {
		rolesData[id] = map[string]any{"grants": stringsToAny(r.Grants)}
	}
	return map[string]any{
		"actions": stringsToAny(actions.Actions),
		"roles":   rolesData,
	}, nil
}

// parseRoleGrants reads the embedded roles.json and returns the role-id -> grant-list map backing PermissionsForRoleIDs. It parses
// the same bytes loadDataBundle feeds the OPA store, so the UI's permission set and the chokepoint's grant data come from one source.
func parseRoleGrants() (map[string][]string, error) {
	rolesBytes, err := fs.ReadFile(policyFS, "policy/data/roles.json")
	if err != nil {
		return nil, fmt.Errorf("authz: read roles.json: %w", err)
	}
	var roles struct {
		Roles map[string]struct {
			Grants []string `json:"grants"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(rolesBytes, &roles); err != nil {
		return nil, fmt.Errorf("authz: parse roles.json: %w", err)
	}
	out := make(map[string][]string, len(roles.Roles))
	for id, r := range roles.Roles {
		out[id] = r.Grants
	}
	return out, nil
}

func stringsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// assertActionsParity is the runtime side of the build-time parity check: the policy bundle's actions[] list must match the Go-side
// RegisteredActions() exactly. A drift here would let the chokepoint silently grant on actions the Go side rejects (or vice versa).
// The parity check in policy_test.go runs the same comparison, but having it at construction time means a misconfigured pilot
// deployment fails fast at boot rather than at first denied request.
func assertActionsParity(data map[string]any) error {
	rawActions, ok := data["actions"].([]any)
	if !ok {
		return errors.New("authz: actions.json missing 'actions' array")
	}
	bundleSet := make(map[string]struct{}, len(rawActions))
	for _, a := range rawActions {
		s, ok := a.(string)
		if !ok {
			return fmt.Errorf("authz: actions.json contains non-string entry %T", a)
		}
		bundleSet[s] = struct{}{}
	}
	goSet := make(map[string]struct{}, len(api.RegisteredActions()))
	for _, a := range api.RegisteredActions() {
		goSet[string(a)] = struct{}{}
	}
	var missingFromBundle, missingFromGo []string
	for s := range goSet {
		if _, ok := bundleSet[s]; !ok {
			missingFromBundle = append(missingFromBundle, s)
		}
	}
	for s := range bundleSet {
		if _, ok := goSet[s]; !ok {
			missingFromGo = append(missingFromGo, s)
		}
	}
	if len(missingFromBundle) == 0 && len(missingFromGo) == 0 {
		return nil
	}
	return fmt.Errorf(
		"authz: action enumeration drift; missing from policy bundle: [%s]; missing from Go RegisteredActions: [%s]",
		strings.Join(missingFromBundle, ","),
		strings.Join(missingFromGo, ","),
	)
}

// decisionFromResultSet pulls the {allow, reason} object out of
// rego.ResultSet. The Rego module always returns a single decision;
// an empty result set means the policy fell through without matching
// the default rule, which is a Rego authoring bug: treat it as
// engine_error so the operator sees something is wrong rather than
// a silent deny.
//
// Both `allow` and `reason` MUST be present and the right Go type.
// A missing or mistyped field is a Rego authoring bug too: silently
// returning `{Allow:false, Reason:""}` would record an empty audit
// reason that's indistinguishable from a real policy result, masking
// a regression that is most easily seen at PR-test time. Error here
// so the engine_error path in Allow records a distinguishable audit
// row and the upstream handler responds 503 instead of 403.
func decisionFromResultSet(rs rego.ResultSet) (api.Decision, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return api.Decision{}, errors.New("authz: empty rego result set")
	}
	val, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return api.Decision{}, fmt.Errorf("authz: unexpected decision shape %T", rs[0].Expressions[0].Value)
	}
	allow, ok := val["allow"].(bool)
	if !ok {
		return api.Decision{}, fmt.Errorf("authz: decision 'allow' field has unexpected type %T", val["allow"])
	}
	reason, ok := val["reason"].(string)
	if !ok {
		return api.Decision{}, fmt.Errorf("authz: decision 'reason' field has unexpected type %T", val["reason"])
	}
	return api.Decision{Allow: allow, Reason: reason}, nil
}

// Compile-time guard: *Engine satisfies api.AuthZ. Renaming the interface or its method breaks compilation here before the consumer
// packages do; this catches signature drift during refactors.
var _ api.AuthZ = (*Engine)(nil)
