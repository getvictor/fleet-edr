// Package attrkeys centralises OTel span + slog attribute keys that are used across
// multiple server packages. Keeping them in one place prevents drift (one call site
// emits `edr.user_id`, another `edr.user.id`, and SigNoz dashboards silently split).
package attrkeys

const (
	// HostID identifies an enrolled endpoint (a UUID string produced at enrollment).
	HostID = "edr.host_id"
	// UserID identifies the authenticated web user (int64).
	UserID = "edr.user.id"
	// UserEmail is the web user email. Never include in the client-facing response body.
	UserEmail = "edr.user.email"
	// RemoteAddr is the source IP of the HTTP request (port stripped).
	RemoteAddr = "edr.remote_addr"
	// AgentVersion is the version string reported by the agent at enrollment.
	AgentVersion = "edr.agent_version"

	// AuthAction is "login" / "logout".
	AuthAction = "edr.auth.action"
	// AuthResult is "ok" / "fail".
	AuthResult = "edr.auth.result"
	// AuthReason is a short machine-readable code for why an auth attempt failed.
	AuthReason = "edr.auth.reason"

	// AdminAction is the admin operation ("revoke", "policy_update", "alert_update", ...).
	AdminAction = "edr.admin.action"
	// AdminActor is the human or automation identity performing the admin action.
	AdminActor = "edr.admin.actor"
	// AdminReason is the free-text reason an admin supplied with the action.
	AdminReason = "edr.admin.reason"

	// SessionIDPrefix is the first 8 hex chars of a session id, safe to log.
	SessionIDPrefix = "edr.session.id_prefix"
)
