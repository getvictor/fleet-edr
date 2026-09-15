//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/testkit"
	responseapi "github.com/fleetdm/edr/server/response/api"
)

// TestAuthZJourney_AnalystDeniedSeniorAllowedAuditorReads is the
// headline cross-context test for the user-management arc. It walks
// the wave-1 RBAC story end-to-end:
//
//  1. An OIDC-provisioned analyst attempts host.isolate by containing
//     a host through POST /api/hosts/{host_id}/containment ->
//     chokepoint denies with no_matching_rule and the response carries
//     the reason header.
//  2. A senior_analyst contains an enrolled host -> chokepoint allows;
//     the host is contained and a set_network_containment command is
//     queued for it.
//  3. A senior_analyst with a stale session attempts the same ->
//     chokepoint denies with reauth_required (freshness gate).
//  4. An auditor reads /api/audit-events -> sees the deny + allow
//     authz.host.isolate rows. The auditor subtest seeds its own
//     analyst + senior_analyst pair and emits the deny/allow chain
//     itself, so it stays runnable in isolation (go test -run
//     ...auditor_reads_journey_audit_rows) without depending on the
//     earlier subtests' side effects.
//
// If this test goes red on a future PR, the wave-1 ship promise
// (operators see the alerts they're allowed to see; destructive
// actions are gated; the audit log is operator-readable) is broken.
// Each subtest is a self-contained fixture so a regression on any
// one pinpoints the broken path.
func TestAuthZJourney_AnalystDeniedSeniorAllowedAuditorReads(t *testing.T) {
	t.Parallel()
	stack := Setup(t)

	t.Run("analyst_denied_isolate", func(t *testing.T) {
		analyst := testkit.SeedJITUser(t, stack.DB, "analyst@journey.test", "analyst")
		resp := postContainment(t, stack, analyst, "host-journey-1")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"analyst must be denied host.isolate at the chokepoint")
		assert.Equal(t, identityapi.ReasonNoMatchingRule, resp.Header.Get(identityapi.AuthzReasonHeader),
			"deny reason header carries the policy verdict for the analyst path")
	})

	// spec:server-host-containment/an-operator-contains-or-releases-a-host/an-operator-contains-a-host
	t.Run("senior_analyst_allowed_isolate", func(t *testing.T) {
		const hostID = "B0B0B0B0-2222-3333-4444-555566667777"
		stepEnroll(t, stack, hostID)
		senior := testkit.SeedJITUser(t, stack.DB, "senior@journey.test", "senior_analyst")
		resp := postContainment(t, stack, senior, hostID)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode,
			"senior_analyst must be allowed host.isolate; got header reason=%q",
			resp.Header.Get(identityapi.AuthzReasonHeader))
		var got responseapi.ContainmentChange
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.True(t, got.Changed)
		assert.True(t, got.State.Contained)
		assert.Equal(t, int64(1), got.State.Version)
		require.NotZero(t, got.CommandID, "the containment change queues a set_network_containment command")
		cmd, err := stack.ResponseService().Get(t.Context(), got.CommandID)
		require.NoError(t, err)
		assert.Equal(t, responseapi.CommandTypeSetNetworkContainment, cmd.CommandType)
		assert.JSONEq(t, fmt.Sprintf(`{"version":1,"epoch":%d,"contained":true}`, got.State.Epoch), string(cmd.Payload))
	})

	t.Run("senior_analyst_denied_after_reauth_window", func(t *testing.T) {
		stale := testkit.SeedJITUser(t, stack.DB, "stale-senior@journey.test", "senior_analyst")
		// Age the session past the default 30-minute reauth window so SessionFresh evaluates false. The Rego policy then layers a
		// reauth_required deny on top of the otherwise-granting role.
		testkit.AgeSession(t, stack.DB, stale.ID, time.Hour)

		resp := postContainment(t, stack, stale, "host-journey-3")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"stale-session senior_analyst must be denied with reauth_required")
		assert.Equal(t, identityapi.ReasonReauthRequired, resp.Header.Get(identityapi.AuthzReasonHeader),
			"deny reason carries the freshness-gate verdict for the UI to render an inline reauth prompt")
	})

	t.Run("auditor_reads_journey_audit_rows", func(t *testing.T) {
		// Self-contained: seed the analyst + senior_analyst pair this subtest cares about and emit the deny + allow chain
		// inline, rather than relying on the preceding subtests' side effects. Keeps the subtest runnable in isolation (go
		// test -run ...) and pins exactly which audit rows the auditor must see.
		analyst := testkit.SeedJITUser(t, stack.DB, "analyst-aud@journey.test", "analyst")
		denyResp := postContainment(t, stack, analyst, "host-journey-aud-deny")
		denyResp.Body.Close()
		require.Equal(t, http.StatusForbidden, denyResp.StatusCode,
			"audit-row prep: analyst must be denied so a deny row lands in audit_events")

		senior := testkit.SeedJITUser(t, stack.DB, "senior-aud@journey.test", "senior_analyst")
		allowResp := postContainment(t, stack, senior, "host-journey-aud-allow")
		allowResp.Body.Close()
		// The chokepoint allows it; the host is not enrolled, so the change itself is refused after the allow row is written.
		require.Equal(t, http.StatusNotFound, allowResp.StatusCode,
			"audit-row prep: senior_analyst must be allowed so an allow row lands in audit_events")

		auditor := testkit.SeedJITUser(t, stack.DB, "auditor@journey.test", "auditor")
		req := newGet(t, stack.Server.URL+"/api/audit-events?action=authz.host.isolate&limit=50", auditor)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equalf(t, http.StatusOK, resp.StatusCode,
			"auditor must be allowed audit.read; got header reason=%q",
			resp.Header.Get(identityapi.AuthzReasonHeader))
		var body struct {
			Items []identityapi.AuditRow `json:"items"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

		var sawDeny, sawAllow bool
		for _, row := range body.Items {
			if row.Action != identityapi.AuditAction("authz.host.isolate") {
				continue
			}
			if row.UserID == nil {
				continue
			}
			allow, _ := row.Payload["allow"].(bool)
			reason, _ := row.Payload["reason"].(string)
			switch {
			case *row.UserID == analyst.ID && !allow && reason == identityapi.ReasonNoMatchingRule:
				sawDeny = true
			case *row.UserID == senior.ID && allow && reason == identityapi.ReasonGranted:
				sawAllow = true
			}
		}
		assert.True(t, sawDeny, "auditor must see the analyst's deny row for this subtest; rows=%+v", body.Items)
		assert.True(t, sawAllow, "auditor must see the senior_analyst's allow row for this subtest; rows=%+v", body.Items)
	})
}

// postContainment contains hostID through POST /api/hosts/{host_id}/containment with the seeded user's session + CSRF token, the
// endpoint host.isolate gates. Centralised so each subtest reads cleanly as "verb the action; assert the response."
func postContainment(t *testing.T, stack *Stack, user testkit.SeededUser, hostID string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		stack.Server.URL+"/api/hosts/"+hostID+"/containment", strings.NewReader(`{"contained":true,"reason":"authz journey"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(identityapi.CSRFHeaderName, user.CSRFToken)
	req.AddCookie(&http.Cookie{Name: identityapi.SessionCookieName, Value: user.SessionCookie})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// newGet builds an authenticated GET request with the session cookie. GET is a safe method so the CSRF middleware does not require
// the X-Csrf-Token header; the cookie alone is enough to pass the session middleware, which is what the read-side endpoint gates on.
// Tests that hit unsafe methods use postCommand above.
func newGet(t *testing.T, url string, user testkit.SeededUser) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: identityapi.SessionCookieName, Value: user.SessionCookie})
	return req
}
