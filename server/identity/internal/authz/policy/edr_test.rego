# Policy-side correctness suite. The Go-side policy_test.go runs this
# against edr.rego + the data bundle via the OPA tester library
# (semantics match `opa test policy/` exactly, no CLI required) and
# fails the build on any failing case. Numeric coverage is not gated
# in wave 1; the matrix below + engine_test.go's Go-side cells form
# the correctness floor.
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
			"session_fresh": true,
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
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "senior_analyst", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
			"session_fresh": true,
		},
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
			"session_fresh": true,
		},
		"action": "host.isolate",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": true, "reason": "granted"}
}

# --- Phase 5 reauth window: destructive actions deny with
#     reauth_required when the role grants the action but session
#     freshness is stale. Lower severities pass through.

test_admin_can_isolate_host_when_session_fresh if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
			"session_fresh": true,
		},
		"action": "host.isolate",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": true, "reason": "granted"}
}

test_admin_isolate_host_denied_when_stale if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
			"session_fresh": false,
		},
		"action": "host.isolate",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": false, "reason": "reauth_required"}
}

test_admin_kill_process_denied_when_stale if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
			"session_fresh": false,
		},
		"action": "host.kill_process",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": false, "reason": "reauth_required"}
}

test_admin_run_script_denied_when_stale if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
			"session_fresh": false,
		},
		"action": "host.run_script",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": false, "reason": "reauth_required"}
}

# Critical-severity alert.resolve is reauth-gated; lower severities
# pass through even with a stale session. The handler is responsible
# for fetching alert.severity before the gate.

test_admin_resolve_critical_alert_denied_when_stale if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
			"session_fresh": false,
		},
		"action": "alert.resolve",
		"resource": {"tenant_id": "default", "type": "alert", "id": "12", "severity": "critical"},
	}
	d == {"allow": false, "reason": "reauth_required"}
}

test_admin_resolve_high_alert_allowed_when_stale if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
			"session_fresh": false,
		},
		"action": "alert.resolve",
		"resource": {"tenant_id": "default", "type": "alert", "id": "12", "severity": "high"},
	}
	d == {"allow": true, "reason": "granted"}
}

# Critical defense-in-depth: an analyst (no role granting host.isolate)
# hitting the destructive surface MUST see no_matching_rule, not
# reauth_required. Otherwise the wire response leaks role information
# to a probing attacker.

test_analyst_isolate_host_says_no_matching_rule_not_reauth if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "analyst", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
			"session_fresh": false,
		},
		"action": "host.isolate",
		"resource": {"tenant_id": "default", "type": "host", "id": "abc"},
	}
	d == {"allow": false, "reason": "no_matching_rule"}
}

# Reads + non-destructive lifecycle actions are NOT reauth-gated even
# when the actor's session is stale — the freshness window applies
# only to the destructive set.

test_admin_read_host_unaffected_by_stale_session if {
	d := authz.decision with input as {
		"actor": {
			"tenant_id": "default",
			"roles": [{"role_id": "admin", "tenant_id": "default", "scope_type": "tenant", "scope_id": "*"}],
			"session_fresh": false,
		},
		"action": "host.read",
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
