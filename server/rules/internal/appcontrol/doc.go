// Package appcontrol is the rules-context subdomain for the
// Application Control subsystem. It owns the durable representation
// of policies and rules (the `app_control_policies` +
// `app_control_rules` tables), the per-rule_type identifier
// validators, and the lookup paths the REST handler and the agent
// fan-out consume.
//
// v0.1.0 ships every wire-enum rule type wired through to the
// extension's AUTH_EXEC walker: BINARY, CDHASH, SIGNINGID, TEAMID
// (Phase A close-out, PR #289), plus CERTIFICATE and PATH (Phase B
// close-out, PR for #210). The validator's only rejection branch is
// ErrAppControlInvalidRuleType for tokens that aren't on the enum at
// all. ErrAppControlUnsupportedRuleType is retained on the api
// package for the future case where a new wire-enum value lands
// before its extension-side support; no validator branch produces it
// today.
package appcontrol
