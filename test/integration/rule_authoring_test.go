//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/testkit"
)

// authoredRule renders a minimal but real Sigma document, so this exercises the actual loader rather than a shape invented here.
func authoredRule(title, id string) string {
	return "title: " + title + "\n" +
		"id: " + id + "\n" +
		"status: test\ndescription: integration fixture\nauthor: test\n" +
		"logsource:\n    category: process_creation\n    product: macos\n" +
		"detection:\n    selection:\n        Image|endswith: '/osascript'\n    condition: selection\n" +
		"level: medium\n"
}

// rcRequest issues an authenticated request against the rule-content surface.
func rcRequest(t *testing.T, stack *Stack, user testkit.SeededUser, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, stack.Server.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(identityapi.CSRFHeaderName, user.CSRFToken)
	req.AddCookie(&http.Cookie{Name: identityapi.SessionCookieName, Value: user.SessionCookie})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

// spec:rule-content/every-authoring-change-is-attributable/a-write-is-attributed
// spec:rule-content/every-authoring-change-is-attributable/a-deletion-is-attributed
//
// TestRuleAuthoring_EndToEnd walks the whole surface against the real store, the real loader, the real chokepoint and the real
// audit recorder, which is the only place all four meet.
//
// The unit tests cover each in isolation with fakes, and that is where the branch coverage lives. What this adds is the thing
// fakes cannot show: that the corpus a write lands in is the corpus the loader validated against, and that the audit row a
// reviewer will read actually reaches the table.
func TestRuleAuthoring_EndToEnd(t *testing.T) { //nolint:tparallel // ordered walk over one corpus; see the doc comment
	t.Parallel()
	stack := Setup(t)
	admin := testkit.SeedJITUser(t, stack.DB, "author@rules.test", "admin")
	// The trail is read as an AUDITOR, not as the admin who made the change. admin does not hold audit.read; only auditor does,
	// which is the separation working rather than a gap, and it means the reader of a change is never the author of it.
	auditor := testkit.SeedJITUser(t, stack.DB, "auditor@rules.test", "auditor")

	const path = "/api/v1/rule-content/documents/authored/integration_authored_rule.yml"
	body := func(reason string) string {
		payload, err := json.Marshal(map[string]string{
			"content": authoredRule("Integration Authored Rule", "aaaaaaaa-1111-4111-8111-111111111111"),
			"reason":  reason,
		})
		require.NoError(t, err)
		return string(payload)
	}

	t.Run("a check reports the change would apply, and changes nothing", func(t *testing.T) {
		payload, err := json.Marshal(map[string]string{
			"path":    "authored/integration_authored_rule.yml",
			"content": authoredRule("Integration Authored Rule", "aaaaaaaa-1111-4111-8111-111111111111"),
		})
		require.NoError(t, err)
		status, got := rcRequest(t, stack, admin, http.MethodPost,
			"/api/v1/rule-content/documents:check", string(payload))
		require.Equal(t, http.StatusOK, status, got)
		assert.Contains(t, got, `"would_apply":true`)

		listStatus, list := rcRequest(t, stack, admin, http.MethodGet, "/api/v1/rule-content/documents", "")
		require.Equal(t, http.StatusOK, listStatus)
		assert.NotContains(t, list, "integration_authored_rule", "a check must not store anything")
	})

	t.Run("the write lands and is readable back verbatim", func(t *testing.T) {
		status, got := rcRequest(t, stack, admin, http.MethodPut, path, body("adding coverage for osascript"))
		require.Equal(t, http.StatusOK, status, got)

		readStatus, content := rcRequest(t, stack, admin, http.MethodGet, path, "")
		require.Equal(t, http.StatusOK, readStatus)
		assert.Equal(t, authoredRule("Integration Authored Rule", "aaaaaaaa-1111-4111-8111-111111111111"), content,
			"the stored document must come back byte for byte, since it is the artifact an operator edits")
	})

	t.Run("the write is attributed in the audit trail", func(t *testing.T) {
		req := newGet(t, stack.Server.URL+"/api/audit-events?action=rule_content.document_put&limit=50", auditor)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// "items", not "events": the envelope key is what the audit surface actually emits, and a struct naming the wrong one
		// decodes to an empty slice without erroring, which is a test that cannot fail for the reason it claims.
		var page struct {
			Items []struct {
				Action   string `json:"action"`
				TargetID string `json:"target_id"`
				Actor    struct {
					ID    string `json:"id"`
					Label string `json:"label"`
				} `json:"actor"`
				Payload map[string]any `json:"payload"`
			} `json:"items"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&page))

		var found bool
		for _, e := range page.Items {
			if e.TargetID != "authored/integration_authored_rule.yml" {
				continue
			}
			found = true
			assert.Equal(t, "rule_content.document_put", e.Action)
			assert.Equal(t, "author@rules.test", e.Actor.Label, "attributed to the operator who made the change")
			assert.Equal(t, "adding coverage for osascript", e.Payload["reason"],
				"the row must carry why, which is the field a reviewer is actually asking about")
		}
		assert.True(t, found, "the write must be attributable: items=%+v", page.Items)
	})

	t.Run("the authored rule reaches the running catalog", func(t *testing.T) {
		// The corpus version moved, so a reload adopts it. This is the property that makes authoring worth anything: a rule an
		// operator stored has to actually be evaluated, and the stored-root behaviour is what carries an authored/ path through.
		n, err := stack.Rules.Reload(t.Context())
		require.NoError(t, err)
		require.Positive(t, n)

		var ids []string
		for _, rm := range stack.Rules.Catalog().List() {
			ids = append(ids, rm.ID)
		}
		assert.Contains(t, ids, "integration_authored_rule",
			"a stored rule must be in force after a reload, or authoring it accomplished nothing")
	})

	t.Run("a second sequential write succeeds, each against the version it read", func(t *testing.T) {
		// Named for what it actually shows. An earlier name claimed this covered the stale-version CONFLICT, which it does not:
		// the request is sequential and reads the current version internally, so it is expected to succeed. Leaving that name in
		// place would have made the conflict path look integration-tested when the only thing covering it is the store test that
		// drives two writes against one version.
		status, got := rcRequest(t, stack, admin, http.MethodPut, path, body("second edit"))
		require.Equal(t, http.StatusOK, status, got)
	})

	t.Run("the delete lands and is attributed", func(t *testing.T) {
		status, got := rcRequest(t, stack, admin, http.MethodDelete, path, `{"reason":"superseded"}`)
		require.Equal(t, http.StatusOK, status, got)

		readStatus, _ := rcRequest(t, stack, admin, http.MethodGet, path, "")
		assert.Equal(t, http.StatusNotFound, readStatus, "a deleted document must be gone")

		req := newGet(t, stack.Server.URL+"/api/audit-events?action=rule_content.document_delete&limit=50", auditor)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		var page struct {
			Items []struct {
				TargetID string `json:"target_id"`
			} `json:"items"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&page))
		var found bool
		for _, e := range page.Items {
			if e.TargetID == "authored/integration_authored_rule.yml" {
				found = true
			}
		}
		assert.True(t, found, "the deletion must be attributable too: items=%+v", page.Items)
	})
}

// spec:rule-content/operators-reach-authoring-through-a-governed-surface/an-operator-without-write-permission-cannot-change-rule-content
//
// TestRuleAuthoring_SeniorAnalystReadsButCannotWrite walks the band split against the real policy bundle rather than a fake
// authorizer. The unit test asserts the handler honours a decision; this asserts the deployment's own roles produce it.
func TestRuleAuthoring_SeniorAnalystReadsButCannotWrite(t *testing.T) {
	t.Parallel()
	stack := Setup(t)
	senior := testkit.SeedJITUser(t, stack.DB, "senior@rules.test", "senior_analyst")
	analyst := testkit.SeedJITUser(t, stack.DB, "analyst@rules.test", "analyst")

	readStatus, _ := rcRequest(t, stack, senior, http.MethodGet, "/api/v1/rule-content/documents", "")
	assert.Equal(t, http.StatusOK, readStatus, "senior_analyst is granted rule_content.read")

	writeStatus, _ := rcRequest(t, stack, senior, http.MethodPut,
		"/api/v1/rule-content/documents/authored/senior_attempt.yml",
		fmt.Sprintf(`{"content":%q,"reason":"attempt"}`, authoredRule("Senior Attempt", "bbbbbbbb-1111-4111-8111-111111111111")))
	assert.Equal(t, http.StatusForbidden, writeStatus, "and is NOT granted rule_content.write")

	analystStatus, _ := rcRequest(t, stack, analyst, http.MethodGet, "/api/v1/rule-content/documents", "")
	assert.Equal(t, http.StatusForbidden, analystStatus, "analyst holds neither")
}
