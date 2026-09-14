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

// spec:server-application-control/rule-enforcement-is-required-and-changeable/a-rule-created-in-detect-reaches-hosts-in-detect
func TestAppControlREST_CreateRule_Enforcement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		enforcement string
		want        rulesapi.Enforcement
		hashDigit   string
	}{
		{name: "detect is stored, pushed and audited", enforcement: "DETECT", want: rulesapi.EnforcementDetect, hashDigit: "a"},
		{name: "protect is stored, pushed and audited", enforcement: "PROTECT", want: rulesapi.EnforcementProtect, hashDigit: "b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newAppControlRig(t, []string{"host-a", "host-b"})
			identifier := strings.Repeat(tc.hashDigit, 64)
			body := map[string]any{
				"rule_type":   rulesapi.RuleTypeBinary,
				"identifier":  identifier,
				"enforcement": tc.enforcement,
				"reason":      "enforcement on create",
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

// spec:server-application-control/rule-enforcement-is-required-and-changeable/promoting-a-rule-pushes-and-audits-the-new-enforcement
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

// spec:server-application-control/rule-enforcement-is-required-and-changeable/a-rule-created-without-an-enforcement-is-rejected
// spec:server-application-control/rule-enforcement-is-required-and-changeable/an-unknown-enforcement-is-rejected
func TestAppControlREST_UnknownEnforcementIsRejected(t *testing.T) {
	t.Parallel()
	t.Run("create without the field", func(t *testing.T) {
		t.Parallel()
		r := newAppControlRig(t, []string{"host-a"})
		policyID := r.defaultPolicyID(t)
		resp := r.do(t, http.MethodPost, "/api/v1/app-control/policies/"+i64(policyID)+"/rules", map[string]any{
			"rule_type": rulesapi.RuleTypeBinary, "identifier": strings.Repeat("c", 64), "reason": "no enforcement named",
		})
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		var body map[string]string
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Contains(t, body["message"], "enforcement is required", "the refusal says what is missing")
		rules, err := r.rules.ApplicationControlStore().ListRulesByPolicy(t.Context(), policyID)
		require.NoError(t, err)
		assert.Empty(t, rules, "and nothing is stored")
		assert.Empty(t, r.inserter.snapshot())
	})
	for _, value := range []any{"AUDIT", "detect", "", 1, nil} {
		t.Run("create "+jsonLabel(t, value), func(t *testing.T) {
			t.Parallel()
			r := newAppControlRig(t, []string{"host-a"})
			policyID := r.defaultPolicyID(t)
			resp := r.do(t, http.MethodPost, "/api/v1/app-control/policies/"+i64(policyID)+"/rules", map[string]any{
				"rule_type": rulesapi.RuleTypeBinary, "identifier": strings.Repeat("c", 64), "enforcement": value, "reason": "bad",
			})
			defer resp.Body.Close()
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
			// An explicit null sits beside a real change, which it must not let through as "leave enforcement alone".
			resp := r.do(t, http.MethodPatch, "/api/v1/app-control/rules/"+i64(ruleID), map[string]any{
				"enforcement": value, "severity": "high", "reason": "bad",
			})
			defer resp.Body.Close()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			stored, err := r.rules.ApplicationControlStore().GetRuleByID(t.Context(), ruleID)
			require.NoError(t, err)
			assert.Equal(t, rulesapi.EnforcementProtect, stored.Enforcement, "a rejected update changes nothing")
			assert.Equal(t, rulesapi.SeverityRuleMedium, stored.Severity, "not even a field sent beside it")
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

// spec:server-application-control/rule-enforcement-is-required-and-changeable/a-bulk-upsert-names-each-rule-s-enforcement
func TestAppControlREST_BulkUpsert_Enforcement(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	path := "/api/v1/app-control/policies/" + i64(policyID) + "/rules:bulkUpsert"
	detectID, protectID := strings.Repeat("8", 64), "EQHXZ8M8AV"
	upsert := func(items ...map[string]any) *http.Response {
		return r.do(t, http.MethodPost, path, map[string]any{"rules": items, "reason": "bulk enforcement"})
	}
	storedEnforcement := func() map[string]rulesapi.Enforcement {
		rules, err := r.rules.ApplicationControlStore().ListRulesByPolicy(t.Context(), policyID)
		require.NoError(t, err)
		got := map[string]rulesapi.Enforcement{}
		for _, rule := range rules {
			got[rule.Identifier] = rule.Enforcement
		}
		return got
	}

	resp := upsert(
		map[string]any{"rule_type": "BINARY", "identifier": detectID, "enforcement": "DETECT"},
		map[string]any{"rule_type": "TEAMID", "identifier": protectID},
	)
	resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "an item without enforcement rejects the whole batch")
	assert.Empty(t, storedEnforcement(), "and nothing is stored")

	resp = upsert(
		map[string]any{"rule_type": "BINARY", "identifier": detectID, "enforcement": "DETECT"},
		map[string]any{"rule_type": "TEAMID", "identifier": protectID, "enforcement": "PROTECT"},
	)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, map[string]rulesapi.Enforcement{detectID: rulesapi.EnforcementDetect, protectID: rulesapi.EnforcementProtect},
		storedEnforcement())

	events := r.audit.snapshot()
	require.NotEmpty(t, events)
	assert.Equal(t, 1, events[len(events)-1].Payload["rules_detect"], "the single bulk audit event says how the batch set enforcement")
	assert.Equal(t, 1, events[len(events)-1].Payload["rules_protect"])

	resp = upsert(map[string]any{"rule_type": "BINARY", "identifier": detectID, "enforcement": "PROTECT"})
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, rulesapi.EnforcementProtect, storedEnforcement()[detectID], "re-upserting an existing rule updates its enforcement")

	// Two spellings of one path are one rule, so a batch naming both is a duplicate rather than a silent overwrite of the first
	// item's enforcement by the second's.
	resp = upsert(
		map[string]any{"rule_type": "PATH", "identifier": "/tmp/qa-alias", "enforcement": "PROTECT"},
		map[string]any{"rule_type": "PATH", "identifier": "/private/tmp/qa-alias", "enforcement": "DETECT"},
	)
	resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotContains(t, storedEnforcement(), "/private/tmp/qa-alias", "and nothing from the batch is stored")
}
