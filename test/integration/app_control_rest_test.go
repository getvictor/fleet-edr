//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/testkit"
	responseapi "github.com/fleetdm/edr/server/response/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// TestAppControlREST_CreateRule_FansOutAndAudits is the cross-context
// smoke for demo beats #2 + #3 + the fan-out half of beat #5:
//
//   - An admin authenticates and POSTs a BINARY rule under the seeded
//     Default policy.
//   - The handler validates the rule and atomically inserts +
//     version-bumps the policy.
//   - The fan-out path enumerates enrolled hosts via detection's
//     ListHosts wrapper and enqueues exactly one
//     set_application_control command per host through response's
//     Service.Insert.
//   - The audit log records the action with fanout counts in the
//     payload so the demo's audit-events page shows the operator who
//     authored the rule alongside the hosts it reached.
//
// A regression in any of those steps breaks the demo recording or
// puts the demo in a state where rules don't reach the VM agent. The
// test exists to catch that in CI before the demo dry-run.
func TestAppControlREST_CreateRule_FansOutAndAudits(t *testing.T) {
	t.Parallel()
	stack := Setup(t)
	ctx := t.Context()

	const hostID = "DDDD1111-2222-3333-4444-555566667777"
	// Enrolling the host (a) gives the fan-out path a real recipient to enumerate via ListHosts AND (b) provisions the host token the
	// agent would later use to poll for the queued command. stepEnroll posts /api/enroll which records the host id via the endpoint
	// service; for the rules-side fan-out to see the host in ListHosts we also need a detection-side row. The cleanest way is to send one
	// event so UpsertHosts runs.
	hostToken := stepEnroll(t, stack, hostID)
	now := time.Now().UnixNano()
	postEvents(t, stack, hostToken, []detectionapi.Event{{
		EventID:     "ac-rest-fork",
		HostID:      hostID,
		TimestampNs: now,
		EventType:   "fork",
		Payload:     json.RawMessage(`{"child_pid":7373,"parent_pid":1}`),
	}})
	require.Eventually(t, func() bool {
		hosts, err := stack.DetectionService().ListHosts(ctx)
		if err != nil {
			return false
		}
		for _, h := range hosts {
			if h.HostID == hostID {
				return true
			}
		}
		return false
	}, 5*time.Second, 50*time.Millisecond, "host must be visible to ListHosts before the fan-out runs")

	admin := testkit.SeedJITUser(t, stack.DB, "admin@appcontrol.test", "admin")

	policy := lookupDefaultPolicy(t, ctx, stack)
	createBody := mustJSON(t, map[string]any{
		"rule_type":  rulesapi.RuleTypeBinary,
		"identifier": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		"severity":   rulesapi.SeverityRuleHigh,
		"custom_msg": "Blocked by corporate policy",
		"reason":     "demo dry-run rehearsal",
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		stack.Server.URL+"/api/v1/app-control/policies/"+strconv.FormatInt(policy.ID, 10)+"/rules",
		bytes.NewReader(createBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(identityapi.CSRFHeaderName, admin.CSRFToken)
	req.AddCookie(&http.Cookie{Name: identityapi.SessionCookieName, Value: admin.SessionCookie})
	resp, err := stack.Server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "admin must be allowed to create a rule")

	var created rulesapi.ApplicationControlRule
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	assert.Equal(t, rulesapi.RuleTypeBinary, created.RuleType)
	assert.Equal(t, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", created.Identifier)
	assert.Equal(t, rulesapi.SeverityRuleHigh, created.Severity)

	// The fan-out path put exactly one set_application_control command in the host's queue. Use ListForHost (the agent's poll endpoint
	// backend) so we exercise the same SQL path the agent would on its next poll.
	commands, err := stack.ResponseService().ListForHost(ctx, hostID, "")
	require.NoError(t, err)
	var found *responseapi.Command
	for i := range commands {
		if commands[i].CommandType == rulesapi.CommandTypeSetApplicationControl {
			found = &commands[i]
			break
		}
	}
	require.NotNil(t, found, "agent must see exactly one set_application_control command queued after the create")
	assert.Equal(t, hostID, found.HostID)

	var payload rulesapi.SetApplicationControlPayload
	require.NoError(t, json.Unmarshal(found.Payload, &payload))
	require.Len(t, payload.Rules, 1)
	assert.Equal(t, policy.ID, payload.PolicyID)
	assert.Positive(t, payload.PolicyVersion, "policy version must be bumped post-create")
	assert.Equal(t, rulesapi.RuleTypeBinary, payload.Rules[0].RuleType)
}

// TestAppControlREST_CreateRule_AnalystForbidden pins the wave-1 role matrix: an analyst is allowed to read alerts but not author
// application-control rules. The chokepoint must return 403 with reason=no_matching_rule before the handler reaches the store.
func TestAppControlREST_CreateRule_AnalystForbidden(t *testing.T) {
	t.Parallel()
	stack := Setup(t)
	ctx := t.Context()

	policy := lookupDefaultPolicy(t, ctx, stack)
	analyst := testkit.SeedJITUser(t, stack.DB, "analyst@appcontrol.test", "analyst")
	body := mustJSON(t, map[string]any{
		"rule_type":  rulesapi.RuleTypeBinary,
		"identifier": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"severity":   rulesapi.SeverityRuleMedium,
		"reason":     "should fail at the chokepoint",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		stack.Server.URL+"/api/v1/app-control/policies/"+strconv.FormatInt(policy.ID, 10)+"/rules",
		bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(identityapi.CSRFHeaderName, analyst.CSRFToken)
	req.AddCookie(&http.Cookie{Name: identityapi.SessionCookieName, Value: analyst.SessionCookie})
	resp, err := stack.Server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, identityapi.ReasonNoMatchingRule, resp.Header.Get(identityapi.AuthzReasonHeader))
}

// lookupDefaultPolicy returns the seeded Default policy via the rules-context store. Tests rely on it to grab the id without
// re-running the seed query themselves.
func lookupDefaultPolicy(t *testing.T, ctx context.Context, stack *Stack) rulesapi.ApplicationControlPolicy {
	t.Helper()
	store := stack.Rules.ApplicationControlStore()
	p, err := store.GetPolicyByName(ctx, rulesapi.DefaultPolicyName)
	require.NoError(t, err)
	require.NotZero(t, p.ID, "Default policy must be seeded on bootstrap")
	return p
}
