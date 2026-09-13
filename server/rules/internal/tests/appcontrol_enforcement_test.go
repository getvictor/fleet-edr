//go:build integration

package tests

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// pushedEnforcement decodes every snapshot the rig's fan-out enqueued after skip commands and returns the enforcement each carries
// for identifier. A snapshot that omits the rule reports "", which a test comparing against PROTECT or DETECT reads as a failure.
func pushedEnforcement(t *testing.T, r *appControlRig, skip int, identifier string) []rulesapi.Enforcement {
	t.Helper()
	var got []rulesapi.Enforcement
	for _, c := range r.inserter.snapshot()[skip:] {
		require.Equal(t, rulesapi.CommandTypeSetApplicationControl, c.Type)
		var payload rulesapi.SetApplicationControlPayload
		require.NoError(t, json.Unmarshal(c.Payload, &payload))
		var enforcement rulesapi.Enforcement
		for _, rule := range payload.Rules {
			if rule.Identifier == identifier {
				enforcement = rule.Enforcement
			}
		}
		got = append(got, enforcement)
	}
	return got
}

// spec:server-application-control/rule-enforcement-is-chosen-on-create-and-changed-on-update/a-rule-created-in-detect-reaches-hosts-in-detect
// spec:server-application-control/rule-enforcement-is-chosen-on-create-and-changed-on-update/a-rule-created-without-an-enforcement-blocks
func TestAppControlREST_CreateRule_Enforcement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		enforcement any
		want        rulesapi.Enforcement
		hashDigit   string
	}{
		{name: "detect is stored, pushed and audited", enforcement: "DETECT", want: rulesapi.EnforcementDetect, hashDigit: "a"},
		{name: "protect is stored, pushed and audited", enforcement: "PROTECT", want: rulesapi.EnforcementProtect, hashDigit: "b"},
		{name: "omitted enforcement blocks", enforcement: nil, want: rulesapi.EnforcementProtect, hashDigit: "e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newAppControlRig(t, []string{"host-a", "host-b"})
			identifier := strings.Repeat(tc.hashDigit, 64)
			body := map[string]any{
				"rule_type":  rulesapi.RuleTypeBinary,
				"identifier": identifier,
				"reason":     "enforcement on create",
			}
			if tc.enforcement != nil {
				body["enforcement"] = tc.enforcement
			}
			resp := r.do(t, http.MethodPost, "/api/v1/app-control/policies/"+i64(r.defaultPolicyID(t))+"/rules", body)
			defer resp.Body.Close()
			require.Equal(t, http.StatusCreated, resp.StatusCode)
			var created rulesapi.ApplicationControlRule
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
			assert.Equal(t, tc.want, created.Enforcement)

			stored, err := r.rules.ApplicationControlStore().GetRuleByID(t.Context(), created.ID)
			require.NoError(t, err)
			assert.Equal(t, tc.want, stored.Enforcement, "the stored row carries the enforcement, not just the response")
			assert.Equal(t, []rulesapi.Enforcement{tc.want, tc.want}, pushedEnforcement(t, r, 0, identifier),
				"every host's snapshot carries the rule's enforcement")

			events := r.audit.snapshot()
			require.Len(t, events, 1)
			assert.Equal(t, string(tc.want), events[0].Payload["enforcement"])
		})
	}
}

// spec:server-application-control/rule-enforcement-is-chosen-on-create-and-changed-on-update/promoting-a-rule-pushes-and-audits-the-new-enforcement
func TestAppControlREST_UpdateRule_PromotesEnforcement(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a", "host-b"})
	policyID := r.defaultPolicyID(t)
	identifier := strings.Repeat("7", 64)
	resp := r.do(t, http.MethodPost, "/api/v1/app-control/policies/"+i64(policyID)+"/rules", map[string]any{
		"rule_type": rulesapi.RuleTypeBinary, "identifier": identifier, "enforcement": "DETECT", "reason": "start in detect",
	})
	var created rulesapi.ApplicationControlRule
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	require.Equal(t, rulesapi.EnforcementDetect, created.Enforcement)
	policyBefore, err := r.rules.ApplicationControlStore().GetPolicyByID(t.Context(), policyID)
	require.NoError(t, err)
	pushedBefore := len(r.inserter.snapshot())

	resp = r.do(t, http.MethodPatch, "/api/v1/app-control/rules/"+i64(created.ID), map[string]any{
		"enforcement": "PROTECT", "reason": "a week of would-block records, all expected",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated rulesapi.ApplicationControlRule
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	assert.Equal(t, rulesapi.EnforcementProtect, updated.Enforcement)

	stored, err := r.rules.ApplicationControlStore().GetRuleByID(t.Context(), created.ID)
	require.NoError(t, err)
	assert.Equal(t, rulesapi.EnforcementProtect, stored.Enforcement)
	policyAfter, err := r.rules.ApplicationControlStore().GetPolicyByID(t.Context(), policyID)
	require.NoError(t, err)
	assert.Equal(t, policyBefore.Version+1, policyAfter.Version, "a change of enforcement bumps the policy version")
	assert.Equal(t, []rulesapi.Enforcement{rulesapi.EnforcementProtect, rulesapi.EnforcementProtect},
		pushedEnforcement(t, r, pushedBefore, identifier), "every host receives the promoted rule")

	events := r.audit.snapshot()
	last := events[len(events)-1]
	assert.Equal(t, identityapi.AuditAppControlRuleUpdate, last.Action)
	assert.Equal(t, "PROTECT", last.Payload["enforcement"])
	assert.Equal(t, "a week of would-block records, all expected", last.Payload["reason"])
}

// spec:server-application-control/rule-enforcement-is-chosen-on-create-and-changed-on-update/an-unknown-enforcement-is-rejected
func TestAppControlREST_UnknownEnforcementIsRejected(t *testing.T) {
	t.Parallel()
	for _, value := range []any{"AUDIT", "detect", "", 1} {
		t.Run("create "+jsonLabel(t, value), func(t *testing.T) {
			t.Parallel()
			r := newAppControlRig(t, []string{"host-a"})
			policyID := r.defaultPolicyID(t)
			resp := r.do(t, http.MethodPost, "/api/v1/app-control/policies/"+i64(policyID)+"/rules", map[string]any{
				"rule_type": rulesapi.RuleTypeBinary, "identifier": strings.Repeat("c", 64), "enforcement": value, "reason": "bad",
			})
			defer resp.Body.Close()
			if value == "" {
				// An empty string is the omitted field's zero value on the wire, so it takes the default rather than failing.
				require.Equal(t, http.StatusCreated, resp.StatusCode)
				return
			}
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			rules, err := r.rules.ApplicationControlStore().ListRulesByPolicy(t.Context(), policyID)
			require.NoError(t, err)
			assert.Empty(t, rules, "a rejected create stores nothing")
			assert.Empty(t, r.inserter.snapshot())
			assert.Empty(t, r.audit.snapshot())
		})
		t.Run("update "+jsonLabel(t, value), func(t *testing.T) {
			t.Parallel()
			r := newAppControlRig(t, []string{"host-a"})
			ruleID := seedRule(t, r, r.defaultPolicyID(t), strings.Repeat("d", 64))
			pushedBefore := len(r.inserter.snapshot())
			resp := r.do(t, http.MethodPatch, "/api/v1/app-control/rules/"+i64(ruleID), map[string]any{
				"enforcement": value, "reason": "bad",
			})
			defer resp.Body.Close()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			stored, err := r.rules.ApplicationControlStore().GetRuleByID(t.Context(), ruleID)
			require.NoError(t, err)
			assert.Equal(t, rulesapi.EnforcementProtect, stored.Enforcement, "a rejected update changes nothing")
			assert.Len(t, r.inserter.snapshot(), pushedBefore, "and pushes nothing")
		})
	}
}

// jsonLabel renders a subtest name for a JSON value, so an empty string reads as "" rather than vanishing.
func jsonLabel(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}
