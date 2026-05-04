# Policy-side correctness suite. `opa test --coverage policy/` runs
# this against edr.rego and the data bundle; the Go-side
# policy_test.go shells out to it and gates the build at >= 90%
# coverage on the policy module.
#
# Each test pins one concrete (role, action, resource) decision so a
# Rego edit that subtly changes the matrix shows up here immediately
# rather than only at the chokepoint integration tests.

package edr.authz_test

import data.edr.authz
import rego.v1

# --- super_admin: granted everything via the "*" wildcard. ----------

test_super_admin_can_isolate_host if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "super_admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
		},
		"action": "host.isolate",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": true, "reason": "granted"}
}

test_super_admin_can_read_audit if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": [{"role_id": "super_admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "audit.read",
		"resource": {"tenant_id": "default", "type": "audit", "id": "*"},
	}
	d.allow == true
}

# --- admin: granted policy + host actions, NOT audit.read. ----------

test_admin_can_update_policy if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "policy.update",
		"resource": {"tenant_id": "default", "type": "policy", "id": "default"},
	}
	d.allow == true
}

test_admin_cannot_read_audit if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "audit.read",
		"resource": {"tenant_id": "default", "type": "audit", "id": "*"},
	}
	d == {"allow": false, "reason": "no_matching_rule"}
}

# --- senior_analyst: destructive actions allowed, policy.update denied.

test_senior_analyst_can_kill_process if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": [{"role_id": "senior_analyst", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "host.kill_process",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d.allow == true
}

test_senior_analyst_cannot_update_policy if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": [{"role_id": "senior_analyst", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "policy.update",
		"resource": {"tenant_id": "default", "type": "policy", "id": "default"},
	}
	d.allow == false
}

# --- analyst: read + comment only, no destructive actions. ----------

test_analyst_can_comment_alert if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": [{"role_id": "analyst", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "alert.comment",
		"resource": {"tenant_id": "default", "type": "alert", "id": "12"},
	}
	d.allow == true
}

test_analyst_cannot_isolate_host if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": [{"role_id": "analyst", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "host.isolate",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d.allow == false
}

# --- auditor: investigative reads + audit.read, nothing else. -------

test_auditor_can_read_audit if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": [{"role_id": "auditor", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "audit.read",
		"resource": {"tenant_id": "default", "type": "audit", "id": "*"},
	}
	d.allow == true
}

test_auditor_cannot_acknowledge_alert if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": [{"role_id": "auditor", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "alert.acknowledge",
		"resource": {"tenant_id": "default", "type": "alert", "id": "12"},
	}
	d.allow == false
}

# --- Cross-tenant deny: actor in tenant A can't act on resource in tenant B.

test_actor_in_tenant_a_denied_for_tenant_b_resource if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "tenant_a", "roles": [{"role_id": "admin", "tenant_id": "tenant_a", "scope_type": "tenant", "scope_id": "*"}]},
		"action": "host.isolate",
		"resource": {"tenant_id": "tenant_b", "type": "host", "id": "abc"},
	}
	d == {"allow": false, "reason": "no_matching_rule"}
}

# --- Wave-1 scope behaviour: host-scope binding is persisted but
#     denied with scope_not_yet_supported when no tenant binding
#     would have granted it.

test_host_scope_only_denied_with_distinct_reason if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "host", "scope_id": "abc"}],
		},
		"action": "host.isolate",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": false, "reason": "scope_not_yet_supported"}
}

# When BOTH a tenant binding AND a host-scope binding exist and the
# tenant one would grant, the tenant grant wins — the
# scope_not_yet_supported branch must NOT fire and shadow it.

test_tenant_grant_wins_over_host_scope_deny if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [
				{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"},
				{"role_id": "admin", "tenant_id": "default", "scope_type": "host", "scope_id": "abc"},
			],
		},
		"action": "host.isolate",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": true, "reason": "granted"}
}

# --- No matching role: empty bindings deny with no_matching_rule. ---

test_actor_with_no_bindings_denied if {
	d := authz.decision with input as {
		"actor": {"tenant_id": "default", "roles": []},
		"action": "host.read",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": false, "reason": "no_matching_rule"}
}
