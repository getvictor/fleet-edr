package audit

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/identity/api"
)

// auditDecision + auditReason normalise the two payload shapes the codebase emits (chokepoint's {allow: bool} and breakglass/oidc's
// {decision: str}) so the OTel span dual-emit lands a consistent edr.audit.decision / edr.audit.reason on every row. Pinned so a
// regression doesn't silently break SigNoz's "decision" filter on the audit dashboard.
func TestAuditDecisionAndReason(t *testing.T) {
	cases := []struct {
		name     string
		action   api.AuditAction
		payload  map[string]any
		wantDec  string
		wantReas string
	}{
		{
			name:     "payload.allow=true wins over action suffix",
			action:   "authz.host.read",
			payload:  map[string]any{"allow": true, "reason": "granted"},
			wantDec:  "allow",
			wantReas: "granted",
		},
		{
			name:     "payload.allow=false maps to deny",
			action:   "authz.host.read",
			payload:  map[string]any{"allow": false},
			wantDec:  "deny",
			wantReas: "",
		},
		{
			name:     "payload.decision wins when allow absent",
			action:   "auth.oidc.failure",
			payload:  map[string]any{"decision": "error", "reason": "oidc.unknown_subject"},
			wantDec:  "error",
			wantReas: "oidc.unknown_subject",
		},
		{
			name:     "no payload, .success suffix resolves to allow",
			action:   "auth.oidc.success",
			payload:  nil,
			wantDec:  "allow",
			wantReas: "",
		},
		{
			name:     "no payload, .failure suffix resolves to error",
			action:   "auth.oidc.failure",
			payload:  nil,
			wantDec:  "error",
			wantReas: "",
		},
		{
			name:     ".error suffix resolves to error",
			action:   "auth.oidc.callback.error",
			payload:  nil,
			wantDec:  "error",
			wantReas: "",
		},
		{
			name:     "no payload, unrecognised action resolves to unspecified",
			action:   "user.created",
			payload:  nil,
			wantDec:  "unspecified",
			wantReas: "",
		},
		{
			name:     "non-string reason reads as empty",
			action:   "authz.host.read",
			payload:  map[string]any{"allow": true, "reason": 42},
			wantDec:  "allow",
			wantReas: "",
		},
		{
			name:     "non-bool allow falls through to decision",
			action:   "authz.host.read",
			payload:  map[string]any{"allow": "yes", "decision": "grant"},
			wantDec:  "grant",
			wantReas: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := api.AuditEvent{Action: tc.action, Payload: tc.payload}
			assert.Equal(t, tc.wantDec, auditDecision(e), "decision")
			assert.Equal(t, tc.wantReas, auditReason(e), "reason")
		})
	}
}

// auditLogLevel mirrors the spec table: break-glass actions WARN, failure-suffix actions WARN, payload.allow=false WARN,
// payload.decision in {deny,error} WARN, everything else INFO.
func TestAuditLogLevel(t *testing.T) {
	cases := []struct {
		name string
		e    api.AuditEvent
		want slog.Level
	}{
		{"breakglass success is WARN", api.AuditEvent{Action: api.AuditAuthBreakglassSuccess}, slog.LevelWarn},
		{"breakglass failure is WARN", api.AuditEvent{Action: api.AuditAuthBreakglassFailure}, slog.LevelWarn},
		{".failure suffix is WARN", api.AuditEvent{Action: "auth.oidc.failure"}, slog.LevelWarn},
		{".error suffix is WARN", api.AuditEvent{Action: "auth.oidc.callback.error"}, slog.LevelWarn},
		{"chokepoint deny is WARN", api.AuditEvent{Action: "authz.host.read", Payload: map[string]any{"allow": false}}, slog.LevelWarn},
		{"decision=deny is WARN", api.AuditEvent{Action: "user.update", Payload: map[string]any{"decision": "deny"}}, slog.LevelWarn},
		{"decision=error is WARN", api.AuditEvent{Action: "user.update", Payload: map[string]any{"decision": "error"}}, slog.LevelWarn},
		{"chokepoint allow is INFO", api.AuditEvent{Action: "authz.host.read", Payload: map[string]any{"allow": true}}, slog.LevelInfo},
		{"decision=allow is INFO", api.AuditEvent{Action: "user.update", Payload: map[string]any{"decision": "allow"}}, slog.LevelInfo},
		{"unrecognised action with no payload is INFO", api.AuditEvent{Action: "user.created"}, slog.LevelInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, auditLogLevel(tc.e))
		})
	}
}
