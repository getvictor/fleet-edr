# Wave-1 authorization policy. Evaluates the chokepoint decision for
# every privileged action against the calling actor's role bindings
# and the action / resource pair the handler passed.
#
# Inputs (assembled by server/identity/internal/authz.Engine):
#
#   input.actor.user_id        int64
#   input.actor.tenant_id      string
#   input.actor.is_breakglass  bool
#   input.actor.auth_method    "local_password" | "oidc"
#   input.actor.roles[]        list of role bindings; expired bindings
#                              are filtered out by the Go side, so
#                              every entry here is a live binding
#       .role_id     "super_admin" | "admin" | ...
#       .tenant_id   string (matches actor.tenant_id today; wave-2 MSSP
#                    work introduces cross-tenant bindings)
#       .scope_type  "tenant" | "host_group" | "host"
#       .scope_id    string ("*" for tenant scope)
#   input.actor.session_fresh  bool (Phase 5 reauth-window flag; wave-1
#                              default is false, so policies that gate
#                              on it default to deny — the safe side)
#   input.action               string from server/identity/api.RegisteredActions
#   input.resource.tenant_id   string
#   input.resource.type        "host" | "alert" | "policy" | ...
#   input.resource.id          string ("*" for tenant-wide; concrete id otherwise)
#
# Data:
#
#   data.roles.<role_id>.grants  list of action strings the role grants;
#                                "*" is the wildcard the super_admin row uses

package edr.authz

import rego.v1

# Default decision: deny with no_matching_rule. The Go engine layers
# additional rejection paths on top (action_not_registered, no_actor)
# before invoking Rego; if the policy fails to match anything, we
# deny rather than ever falling through to allow.
default decision := {"allow": false, "reason": "no_matching_rule"}

# Tenant-scope binding grants the action when:
#   - actor has a binding with scope_type == "tenant"
#   - binding.tenant_id matches resource.tenant_id (wave-1 has one
#     tenant; wave-2 cross-tenant bindings will need their own rule)
#   - role's grant list contains the action OR the wildcard "*"
decision := {"allow": true, "reason": "granted"} if {
	some binding in input.actor.roles
	binding.scope_type == "tenant"
	binding.tenant_id == input.resource.tenant_id
	role_grants_action(binding.role_id, input.action)
}

# Non-tenant scopes (host_group, host) are persisted in role_bindings
# but the resolver isn't shipped yet. Deny with a distinguishable
# reason so the Phase 6 dashboard can show "this would have been
# allowed under wave-2 host-scope work" as a separate dimension.
# Only fires when no tenant-scope binding granted the action.
decision := {"allow": false, "reason": "scope_not_yet_supported"} if {
	not granted_via_tenant
	some binding in input.actor.roles
	binding.scope_type != "tenant"
	role_grants_action(binding.role_id, input.action)
}

# True if some tenant-scope binding granted the action. Used by the
# scope_not_yet_supported branch to suppress its deny when the actor
# also has a valid tenant binding.
granted_via_tenant if {
	some binding in input.actor.roles
	binding.scope_type == "tenant"
	binding.tenant_id == input.resource.tenant_id
	role_grants_action(binding.role_id, input.action)
}

# Role grants the action either explicitly (action string is in the
# role's grants list) or via the "*" wildcard (super_admin only today).
role_grants_action(role_id, action) if {
	some grant in data.roles[role_id].grants
	grant == action
}

role_grants_action(role_id, _action) if {
	some grant in data.roles[role_id].grants
	grant == "*"
}
