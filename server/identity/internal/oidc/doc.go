// Package oidc implements the OpenID Connect Authorization Code +
// PKCE flow that backs the primary authentication path.
//
// Wire shape:
//
//	GET /api/auth/login    -> generate state/nonce/PKCE; set signed
//	                          state cookie; 302 to IdP authorization
//	                          endpoint with code_challenge.
//	GET /api/auth/callback -> verify state cookie; exchange code for
//	                          tokens with code_verifier; verify ID
//	                          token signature/iss/aud/expiry/nonce;
//	                          JIT-provision (or look up) the user;
//	                          mint a session with auth_method='oidc';
//	                          302 to the original next URL (default
//	                          /ui/).
//
// Security boundary: the package is a thin wrapper over
// github.com/coreos/go-oidc/v3/oidc + golang.org/x/oauth2, both of
// which are battle-tested. Every claim a token presents passes
// through the verifier (issuer + audience + expiry + nonce + signature)
// before reaching the JIT provisioner. ±2-minute clock skew tolerance
// matches the wave-1 spec.
//
// Lifecycle: the OIDC handler is constructed once at boot and lives
// for the server's process lifetime. The Provider's JWKS cache
// refreshes on signature failure (go-oidc handles this internally).
//
// Dev mode: when EDR_OIDC_ISSUER is unset and
// EDR_AUTH_ALLOW_NO_OIDC=1, identity bootstrap skips constructing
// this package entirely; the routes are not registered, and the only
// way in is the break-glass surface. Production deployments that
// forget to set EDR_OIDC_ISSUER fail closed at config validation.

package oidc
