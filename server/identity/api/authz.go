// Authorization chokepoint surface. A single AuthZ engine every
// privileged handler in detection / rules / response / endpoint /
// identity calls before performing a side effect. The engine is OPA /
// Rego under the hood (see server/identity/internal/authz); this file
// is the public boundary other contexts depend on.
//
// The product is a single-instance deployment, so wave-1 honours
// `scope_type='global'` only (meaning "deployment-wide"). Bindings
// with 'host_group' or 'host' scopes are persisted (the schema column
// reserves them) but the chokepoint denies them with reason
// `scope_not_yet_supported` until the wave-2 resolver ships.

package api

import (
	"context"
	"errors"
)

// Action is the wire-shape identifier of a privileged action. Stable
// across releases; renaming a constant is a contract break (audit-log
// retention queries pivot on the literal string, so do downstream SIEM
// filters). Mirrors the AuditAction convention in audit.go.
//
// Every Action SHALL be registered in the action enumeration. A call
// to AuthZ.Allow with an unregistered action returns
// {Allow:false, Reason:"action_not_registered"} as defense in depth
// against typos and ghost permissions.
type Action string

// The wave-1 action set. Constants live here; the parallel `policy/data/actions.json` mirrors the same set so the OPA bundle can refer
// to them. A build-time parity check (in internal/authz/policy_test.go) fails the build if the two lists drift.
const (
	// Host + process reads.
	ActionHostRead    Action = "host.read"
	ActionProcessRead Action = "process.read"

	// Host destructive actions. The reauth window gates these on
	// actor.session_fresh.
	ActionHostIsolate     Action = "host.isolate"
	ActionHostKillProcess Action = "host.kill_process"
	ActionHostRunScript   Action = "host.run_script"

	// Alert lifecycle.
	ActionAlertRead        Action = "alert.read"
	ActionAlertComment     Action = "alert.comment"
	ActionAlertAcknowledge Action = "alert.acknowledge"
	ActionAlertResolve     Action = "alert.resolve"
	ActionAlertReopen      Action = "alert.reopen"

	// Enrollment management.
	ActionEnrollmentRead        Action = "enrollment.read"
	ActionEnrollmentRevoke      Action = "enrollment.revoke"
	ActionEnrollmentRotateToken Action = "enrollment.rotate_token"

	// User management. Wired up in wave 1 as part of the break-glass flow; the constants exist so the action registry + Rego policy
	// stay coherent.
	ActionUserRead   Action = "user.read"
	ActionUserInvite Action = "user.invite"

	// SSO configuration. Gates reading and mutating the deployment's stored OIDC provider config (issue #375). Held by admin +
	// super_admin; the admin settings read/update/test-connection handlers funnel through the chokepoint on this action.
	ActionSSOManage Action = "sso.manage"

	// Service-account management (issue #376, ADR-0013). Gates the admin surface that creates, lists, rotates, and revokes
	// non-human API principals. Held by admin + super_admin. A service account may itself never bind to a role granting these
	// actions, so it cannot mint or escalate other service accounts.
	ActionServiceAccountRead   Action = "service_account.read"
	ActionServiceAccountCreate Action = "service_account.create"
	ActionServiceAccountRotate Action = "service_account.rotate"
	ActionServiceAccountRevoke Action = "service_account.revoke"

	// Audit-log read.
	ActionAuditRead Action = "audit.read"

	// Application Control. The admin surface manages the policies and rules that the extension consults on every AUTH_EXEC. Read covers
	// the list + detail views; the five mutation verbs each gate a corresponding POST/PATCH/DELETE handler that fans a fresh
	// `set_application_control` command out to every enrolled host on the affected policy. Bulk upsert + host-groups CRUD stay deferred.
	ActionAppControlRead           Action = "application_control.read"
	ActionAppControlRuleCreate     Action = "application_control.rule_create"
	ActionAppControlRuleUpdate     Action = "application_control.rule_update"
	ActionAppControlRuleDelete     Action = "application_control.rule_delete"
	ActionAppControlRuleBulkUpsert Action = "application_control.rule_bulk_upsert"
	ActionAppControlPolicyCreate   Action = "application_control.policy_create"
	ActionAppControlPolicyUpdate   Action = "application_control.policy_update"
	ActionAppControlPolicyDelete   Action = "application_control.policy_delete"
)

// RegisteredActions returns the set of every Action constant declared
// above. The chokepoint uses it to reject unregistered actions; the
// build-time parity check uses it to compare against the policy bundle.
//
// Order is stable but callers SHOULD treat the result as a set. Adding
// a new Action constant requires updating this list AND the
// `policy/data/actions.json` mirror; the parity test fails the build
// otherwise.
func RegisteredActions() []Action {
	return []Action{
		ActionHostRead, ActionProcessRead,
		ActionHostIsolate, ActionHostKillProcess, ActionHostRunScript,
		ActionAlertRead, ActionAlertComment, ActionAlertAcknowledge,
		ActionAlertResolve, ActionAlertReopen,
		ActionEnrollmentRead, ActionEnrollmentRevoke, ActionEnrollmentRotateToken,
		ActionUserRead, ActionUserInvite,
		ActionSSOManage,
		ActionServiceAccountRead, ActionServiceAccountCreate, ActionServiceAccountRotate, ActionServiceAccountRevoke,
		ActionAuditRead,
		ActionAppControlRead,
		ActionAppControlRuleCreate, ActionAppControlRuleUpdate, ActionAppControlRuleDelete, ActionAppControlRuleBulkUpsert,
		ActionAppControlPolicyCreate, ActionAppControlPolicyUpdate, ActionAppControlPolicyDelete,
	}
}

// Resource pins what the action operates on. JSON-marshals into the
// OPA `input.resource` map. Type and ID are populated only when
// meaningful for the action; zero-value strings are valid (e.g.
// unary actions like audit.read against the whole deployment pass
// an empty Type and ID).
//
// Wave 1: Type + ID is enough for the deployment-wide scope evaluation.
// Wave 2 will grow ABAC-shaped fields (labels, source IP, severity)
// here without breaking existing call sites because OPA's input map
// is open.
type Resource struct {
	Type string `json:"type,omitempty"`
	ID   string `json:"id,omitempty"`
	// Severity is set only on alert-typed resources; it conditions the reauth-required gate. alert.resolve when severity=="critical"
	// requires actor.session_fresh; lower severities pass through. Empty string for non-alert resources, and `omitempty` keeps OPA's
	// input.resource map from carrying a meaningless field for them.
	Severity string `json:"severity,omitempty"`
}

// Decision is the chokepoint's response. Reason is the policy-supplied
// label; the audit row records it verbatim so the audit dashboard (and
// any future SIEM exporter) has a stable filter dimension.
//
// Standard reason values:
//
//   - "granted": the policy matched a deployment-wide binding.
//   - "no_matching_rule": no role granted the action.
//   - "scope_not_yet_supported": only non-deployment scopes matched
//     (wave-1 placeholder for the wave-2 host_group + host resolver).
//   - "action_not_registered": the caller passed an Action not in
//     RegisteredActions; defense in depth.
//   - "no_actor": the request reached the chokepoint without an
//     authenticated actor on ctx; the handler should already have
//     returned 401 before this. Audited so a regression that stops
//     pinning the actor is visible.
//   - "reauth_required": the actor has the role to perform the
//     action but session_fresh is false. HTTPGate maps this to 403 +
//     body { error, challenge } that the UI converts into an inline
//     reauth prompt + retry.
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

// Reason* are the canonical Decision.Reason values. Authz callers compare against these constants rather than string literals so a
// rename or addition is a compile error, not a silent drift between the engine, HTTPGate, and the audit-log dashboard.
const (
	ReasonGranted              = "granted"
	ReasonNoMatchingRule       = "no_matching_rule"
	ReasonScopeNotYetSupported = "scope_not_yet_supported"
	ReasonActionNotRegistered  = "action_not_registered"
	ReasonNoActor              = "no_actor"
	ReasonReauthRequired       = "reauth_required"
)

// Actor is built once by session middleware and threaded through
// context.Context. The chokepoint reads Actor.* + Roles to evaluate
// every authorization decision. RoleBinding is the read shape from
// types.go.
//
// SessionFresh is populated by the reauth-window gate; the default is
// false until the session middleware sets it. Destructive-action
// policies that gate on SessionFresh therefore default to deny, which
// is the safe direction.
type Actor struct {
	UserID       int64         `json:"user_id"`
	IsBreakglass bool          `json:"is_breakglass"`
	AuthMethod   string        `json:"auth_method"`
	Roles        []RoleBinding `json:"roles"`
	SessionFresh bool          `json:"session_fresh"`
}

// AuthZ is the chokepoint every privileged handler funnels through.
// One method, two return values: a Decision and an error. A non-nil
// error means infrastructure failure (the OPA engine could not
// evaluate); the handler should respond 503, NOT 403, so a healthy
// retry can succeed. A nil error with Allow=false is a real deny;
// the handler should respond 403 with Decision.Reason in the body
// (or a header) so the operator sees why.
//
// The engine's implementation lives at
// server/identity/internal/authz/Engine; cross-context callers consume
// AuthZ through this interface so the import graph stays clean.
type AuthZ interface {
	Allow(ctx context.Context, action Action, resource Resource) (Decision, error)
}

// ErrAuthZUnavailable is returned by Allow when the underlying engine cannot evaluate (Rego compile error, runtime panic in policy,
// etc.). Handlers SHOULD map it to 503 Service Unavailable so a transient engine outage does not look like a permission deny.
var ErrAuthZUnavailable = errors.New("identity: authz engine unavailable")

// ctx-key for the actor. Unexported so ctx values can only be set via
// WithActor, mirroring the WithUserID / WithSession pattern in types.go.
type actorCtxKey int

const ctxKeyActor actorCtxKey = 1

// WithActor returns a context with the actor pinned. Called by the Session middleware on every authed request and by tests that mint a
// synthetic authenticated context.
func WithActor(ctx context.Context, a *Actor) context.Context {
	return context.WithValue(ctx, ctxKeyActor, a)
}

// ActorFromContext returns the actor pinned by Session middleware (or by tests via WithActor). The second return is false when no
// actor is on ctx (anonymous request, agent-token-only request, or a regression in the middleware); privileged handlers MUST check.
func ActorFromContext(ctx context.Context) (*Actor, bool) {
	v := ctx.Value(ctxKeyActor)
	a, ok := v.(*Actor)
	return a, ok && a != nil
}
