package breakglass

import (
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/fleetdm/edr/server/httpserver"
)

// Wave-1 rate-limit defaults. The break-glass surface gets stricter limits than the SSO login because:
//   - SSO failures produce IdP-side back-pressure (Okta gates first); break-glass authenticates against our DB directly.
//   - Brute force here is more dangerous: a successful break-glass login bypasses every IdP control.
//   - Real operator usage is rare (incidents only), so a tight budget rarely affects legitimate traffic.
const (
	// DefaultPerIPRatePerMin caps requests against any /admin/break-glass* path to 10/min from a single IP. An attacker behind a single
	// egress address exhausts this on the first volley.
	DefaultPerIPRatePerMin = 10

	// DefaultPerEmailFailedRatePerMin caps logins against any single break-glass email at 3/min. Distinct from the per-IP bucket so a
	// botnet spraying many IPs against one email still hits this. NOTE: consume-only token-bucket semantics mean every attempt consumes
	// one slot — a successful login also burns a token, but break-glass logins are rare by design so the wasted slot is acceptable.
	// The pre-attempt consumption is what prevents argon2 + WebAuthn CPU cycles after the budget is exhausted.
	DefaultPerEmailFailedRatePerMin = 3

	// DefaultSetupRatePerMin caps total submissions against /admin/break-glass/setup to 5/min globally. Even an attacker who somehow
	// obtained the token URL cannot replay-redeem at volume; legitimate redemption is a one-shot single-operator action.
	DefaultSetupRatePerMin = 5
)

// RateLimits bundles the three buckets the break-glass surface gates on. Each is a *httpserver.IPLimiter — a generic keyed-bucket
// limiter; the "IP" naming is historical, the limiter itself is keyed on whatever string the caller passes, so we use the same type
// for the per-email and global-setup buckets.
type RateLimits struct {
	PerIP        *httpserver.IPLimiter
	PerEmailFail *httpserver.IPLimiter
	Setup        *httpserver.IPLimiter
}

// NewRateLimits constructs the three buckets from per-minute caps.
// Zero or negative input falls through to the wave-1 default.
func NewRateLimits(perIP, perEmail, setup int) *RateLimits {
	if perIP <= 0 {
		perIP = DefaultPerIPRatePerMin
	}
	if perEmail <= 0 {
		perEmail = DefaultPerEmailFailedRatePerMin
	}
	if setup <= 0 {
		setup = DefaultSetupRatePerMin
	}
	return &RateLimits{
		PerIP:        httpserver.NewIPLimiter(rate.Every(time.Minute/time.Duration(perIP)), perIP),
		PerEmailFail: httpserver.NewIPLimiter(rate.Every(time.Minute/time.Duration(perEmail)), perEmail),
		Setup:        httpserver.NewIPLimiter(rate.Every(time.Minute/time.Duration(setup)), setup),
	}
}

// AllowIP returns true when the caller's IP is within budget for any /admin/break-glass* route. Caller passes the resolved
// httpserver.ClientIP; an empty string short-circuits to false so a missing IP cannot bypass the gate.
func (r *RateLimits) AllowIP(ip string) bool {
	if strings.TrimSpace(ip) == "" {
		return false
	}
	return r.PerIP.Allow(ip)
}

// AllowEmailFail returns true when the email is within the failed-login budget. Caller invokes it AFTER a failed login attempt;
// a passing call means "this email still has budget for another failure". Empty email collapses to the canonical bucket "<unknown>" so
// an attacker cannot game the limit by submitting an empty email field.
func (r *RateLimits) AllowEmailFail(email string) bool {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		key = "<unknown>"
	}
	return r.PerEmailFail.Allow(key)
}

// AllowSetup returns true when the global setup-bucket budget allows another submission. Keyed on the constant "setup" so every caller
// shares a single bucket (the spec calls for a global cap on /setup volume regardless of source).
func (r *RateLimits) AllowSetup() bool {
	return r.Setup.Allow("setup")
}
