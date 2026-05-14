// HTTP-shaped helpers for the authz chokepoint. Pulled into identity/api
// so every operator handler can share one canonical implementation
// instead of each context re-implementing the (svc.Allow → 503/403)
// pattern. Without the share, Sonar reports the same 25-line block
// duplicated five times across detection / rules / response / endpoint /
// audit and fails the new-code duplication gate (PR #119, gate
// FAILURE on new_duplicated_lines_density).
//
// Adding net/http + log/slog to identity/api is a deliberate
// scope-expansion of the public-surface package: the contract of an
// operator handler is now "use the chokepoint AND map its outcome to
// HTTP", and the helper that does the mapping is part of that
// contract. The same package already exports HTTP-adjacent types
// (SessionCookieName, CSRFHeaderName) so the precedent is established.

package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/fleetdm/edr/server/httpserver"
)

// AuthzReasonHeader is the response header an HTTP handler writes when
// the chokepoint denies a privileged action. The operator UI reads it
// to distinguish a policy deny ("forbidden — your role does not grant
// this action") from a session expiry, which would otherwise share
// the 403 status and produce identical UX.
const AuthzReasonHeader = "X-Edr-Authz-Reason"

// HTTPGate is the standard authz pattern every privileged operator
// handler funnels through: evaluate the (action, resource) pair, write
// 503 on engine error (transient infra), 403 + reason header on deny
// (policy decision), and return true only when the handler should
// proceed.
//
// 503 (not 500) on engine failure so the UI's retry semantics for 5xx
// kick in instead of the 401-on-403 redirect-to-login. 403 (not 401)
// on deny so a real "not allowed" doesn't bounce the operator to the
// login screen and lose their work.
//
// The chokepoint records its own audit row; this helper does NOT
// record one. Subsequent state-change audits remain the handler's
// responsibility (the AuditRecorder.Record call at commit time).
func HTTPGate(
	ctx context.Context,
	w http.ResponseWriter,
	az AuthZ,
	logger *slog.Logger,
	action Action,
	res Resource,
) bool {
	d, err := az.Allow(ctx, action, res)
	if err != nil {
		logger.ErrorContext(ctx, "authz", "err", err, "action", string(action))
		httpserver.NoStoreJSON(ctx, logger, w, http.StatusServiceUnavailable, map[string]string{"error": "authz_unavailable"})
		return false
	}
	if !d.Allow {
		w.Header().Set(AuthzReasonHeader, d.Reason)
		if d.Reason == ReasonReauthRequired {
			writeReauthRequired(ctx, logger, w, ReauthChallengeFor(ctx))
			return false
		}
		httpserver.NoStoreJSON(ctx, logger, w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return false
	}
	return true
}

// ReauthChallenge tells the UI which reauth flow to run when the
// chokepoint denies with reason=reauth_required. The UI reads
// AuthMethod to decide between break-glass POST (local_password) and
// OIDC redirect (oidc); ReauthURL is the absolute path to navigate to
// (oidc) or POST against (local_password).
type ReauthChallenge struct {
	AuthMethod string `json:"auth_method"`
	ReauthURL  string `json:"reauth_url"`
}

// ReauthChallengeFor builds the challenge payload for the actor on
// ctx. OIDC actors get the bare /api/auth/login?reauth=1 URL; the UI
// is responsible for appending its own &next=<original-path> so the
// post-reauth redirect lands the operator back on the page that
// triggered the reauth_required deny. Break-glass actors get the
// POST endpoint URL the UI submits credentials against. When no
// actor is on ctx (the no-actor reason path), a zero challenge is
// returned.
func ReauthChallengeFor(ctx context.Context) ReauthChallenge {
	a, ok := ActorFromContext(ctx)
	if !ok {
		return ReauthChallenge{}
	}
	if a.AuthMethod == "oidc" {
		return ReauthChallenge{AuthMethod: "oidc", ReauthURL: "/api/auth/login?reauth=1"}
	}
	return ReauthChallenge{AuthMethod: "local_password", ReauthURL: "/api/auth/reauth"}
}

// writeReauthRequired emits the 403 + body shape the UI's
// useReauthRetry wrapper detects: error="reauth_required" plus an
// embedded challenge object that pins the per-flow reauth URL.
func writeReauthRequired(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, ch ReauthChallenge) {
	httpserver.NoStoreJSON(ctx, logger, w, http.StatusForbidden, map[string]any{
		"error":     ReasonReauthRequired,
		"challenge": ch,
	})
}
