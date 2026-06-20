package serviceaccounts

import (
	"time"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/satoken"
)

// AuthMethodServiceAccount marks an actor authenticated by a service-account bearer token (as opposed to "oidc" / "local_password"
// human sessions). It is set on the resolved Actor so audit and any auth-method-sensitive logic can distinguish machine callers.
const AuthMethodServiceAccount = "service_account"

// verifier is the subset of *satoken.Signer the Authenticator needs; an interface keeps the authenticator unit-testable.
type verifier interface {
	Verify(token string, now time.Time) (satoken.Claims, error)
}

// allowChecker is the subset of *Snapshot the Authenticator needs.
type allowChecker interface {
	Allowed(clientID string, tokenEpoch int64) bool
}

// Authenticator resolves a presented service-account access token into an authz Actor. It performs the stateless signature/expiry/
// audience check (verifier) plus the per-replica revocation check (allowChecker); both must pass. It does no database I/O, so it is
// safe on the API hot path.
type Authenticator struct {
	signer verifier
	snap   allowChecker
}

// NewAuthenticator wires a token verifier and revocation snapshot into an Authenticator.
func NewAuthenticator(signer verifier, snap allowChecker) *Authenticator {
	return &Authenticator{signer: signer, snap: snap}
}

// Authenticate validates token and returns the actor it represents. ok is false for any invalid, expired, wrong-audience, or revoked
// token; the caller maps that to 401 without distinguishing the reason (avoiding an oracle). The resolved actor carries the single
// bound role as a global binding, is marked SessionFresh (a machine has no interactive session to re-freshen, and destructive actions
// are gated by role alone), and has no user id.
func (a *Authenticator) Authenticate(token string, now time.Time) (*api.Actor, bool) {
	claims, err := a.signer.Verify(token, now)
	if err != nil {
		return nil, false
	}
	if !a.snap.Allowed(claims.Subject, claims.Epoch) {
		return nil, false
	}
	return &api.Actor{
		AuthMethod:   AuthMethodServiceAccount,
		SessionFresh: true,
		Roles: []api.RoleBinding{{
			RoleID:    claims.Role,
			ScopeType: api.RoleBindingScopeGlobal,
			ScopeID:   api.RoleBindingScopeWildcard,
		}},
	}, true
}
