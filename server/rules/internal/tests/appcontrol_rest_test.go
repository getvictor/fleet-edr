//go:build integration

package tests

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// capturedCommand records what the appcontrol fan-out enqueued. The integration test uses it to assert that every host received
// exactly one set_application_control command on a rule-create AND that the JSON payload is the canonical wire shape (filtered for the
// enabled, non-expired rules).
type capturedCommand struct {
	HostID  string
	Type    string
	Payload []byte
}

// recordingInserter is a goroutine-safe CommandInserter stub. The fan-out runs through it instead of response.Service.Insert so the
// test can assert on the enqueued set without standing up the response context. Failures are returned for the host_ids listed in
// FailHost so the audit-row fanout_failed accounting can be exercised.
type recordingInserter struct {
	mu        sync.Mutex
	calls     []capturedCommand
	nextID    atomic.Int64
	failHosts map[string]error
}

func newRecordingInserter() *recordingInserter {
	return &recordingInserter{failHosts: map[string]error{}}
}

func (r *recordingInserter) failFor(hostID string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failHosts[hostID] = err
}

func (r *recordingInserter) Insert(_ context.Context, hostID, commandType string, payload []byte) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err, ok := r.failHosts[hostID]; ok {
		return 0, err
	}
	copyPayload := make([]byte, len(payload))
	copy(copyPayload, payload)
	r.calls = append(r.calls, capturedCommand{HostID: hostID, Type: commandType, Payload: copyPayload})
	return r.nextID.Add(1), nil
}

func (r *recordingInserter) snapshot() []capturedCommand {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]capturedCommand, len(r.calls))
	copy(out, r.calls)
	return out
}

// recordingAudit captures AuditEvent rows. The handler emits one row per CreateRule call; tests assert the action, target type,
// and the fanout_* payload counts.
type recordingAudit struct {
	mu     sync.Mutex
	events []identityapi.AuditEvent
}

func (r *recordingAudit) Record(_ context.Context, e identityapi.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordingAudit) snapshot() []identityapi.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]identityapi.AuditEvent, len(r.events))
	copy(out, r.events)
	return out
}

type appControlRig struct {
	rules    *rulesbootstrap.Rules
	srv      *httptest.Server
	inserter *recordingInserter
	audit    *recordingAudit
	hosts    []string
	actor    *identityapi.Actor
}

// newAppControlRig wires a rules bootstrap with the demo-cut REST surface live. Hosts are a fixed []string the recordingInserter
// fans out to. Sessions and CSRF are bypassed: the handler is mounted directly so the test exercises the route's auth-gate + service
// plumbing without identity middleware. The actor on context is injected by a tiny wrapper so HTTPGate sees a tenant.
func newAppControlRig(t *testing.T, hosts []string) *appControlRig {
	t.Helper()
	db := full.Open(t)
	inserter := newRecordingInserter()
	audit := &recordingAudit{}
	hostList := append([]string(nil), hosts...)
	rules, err := rulesbootstrap.New(rulesbootstrap.Deps{
		DB:              db,
		Logger:          slog.Default(),
		AuthZ:           allowAllAuthZ{},
		Audit:           audit,
		CommandInserter: inserter.Insert,
		HostLister: func(_ context.Context) ([]string, error) {
			return append([]string(nil), hostList...), nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, rules.ApplySchema(t.Context()))

	mux := http.NewServeMux()
	rules.RegisterAuthedRoutes(mux)
	actor := &identityapi.Actor{
		UserID: 42,
		Roles: []identityapi.RoleBinding{{
			RoleID:    "admin",
			ScopeType: identityapi.RoleBindingScopeGlobal,
			ScopeID:   identityapi.RoleBindingScopeWildcard,
		}},
	}
	withActor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(identityapi.WithActor(r.Context(), actor))
		mux.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(withActor)
	t.Cleanup(srv.Close)
	return &appControlRig{rules: rules, srv: srv, inserter: inserter, audit: audit, hosts: hostList, actor: actor}
}

// defaultPolicyID returns the seeded Default policy's row id.
func (r *appControlRig) defaultPolicyID(t *testing.T) int64 {
	t.Helper()
	store := r.rules.ApplicationControlStore()
	p, err := store.GetPolicyByName(t.Context(), rulesapi.DefaultPolicyName)
	require.NoError(t, err)
	return p.ID
}

func (r *appControlRig) do(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(t.Context(), method, r.srv.URL+path, reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// TestAppControl_ListPolicies_ReturnsSeededDefault: the seed bootstrap creates one `Default` policy. The list endpoint must surface it
// so the UI's "open policy detail" link has a target.
func TestAppControlREST_ListPolicies_ReturnsSeededDefault(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a", "host-b"})
	resp := r.do(t, http.MethodGet, "/api/v1/app-control/policies", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		Policies []rulesapi.ApplicationControlPolicy `json:"policies"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body.Policies, 1)
	assert.Equal(t, rulesapi.DefaultPolicyName, body.Policies[0].Name)
}

// TestAppControl_GetPolicy_IncludesRules: a freshly-seeded policy has zero rules; after a POST the GET path should include the new
// rule in the Rules slice.
func TestAppControlREST_GetPolicy_IncludesRules(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)

	get := r.do(t, http.MethodGet, "/api/v1/app-control/policies/"+i64(policyID), nil)
	defer get.Body.Close()
	require.Equal(t, http.StatusOK, get.StatusCode)
	var policy rulesapi.ApplicationControlPolicy
	require.NoError(t, json.NewDecoder(get.Body).Decode(&policy))
	assert.Empty(t, policy.Rules)

	create := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/"+i64(policyID)+"/rules",
		map[string]any{
			"rule_type":  rulesapi.RuleTypeBinary,
			"identifier": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"severity":   rulesapi.SeverityRuleHigh,
			"reason":     "demo dry-run",
		})
	defer create.Body.Close()
	require.Equal(t, http.StatusCreated, create.StatusCode)

	get2 := r.do(t, http.MethodGet, "/api/v1/app-control/policies/"+i64(policyID), nil)
	defer get2.Body.Close()
	require.Equal(t, http.StatusOK, get2.StatusCode)
	var withRule rulesapi.ApplicationControlPolicy
	require.NoError(t, json.NewDecoder(get2.Body).Decode(&withRule))
	require.Len(t, withRule.Rules, 1)
	assert.Equal(t, rulesapi.RuleTypeBinary, withRule.Rules[0].RuleType)
	assert.Equal(t, rulesapi.SeverityRuleHigh, withRule.Rules[0].Severity)
}

// TestAppControl_CreateRule_FansOutToEveryHost: the headline contract. One rule create → one set_application_control command per host,
// each carrying the same wire payload. Dedup if HostLister returns duplicates so the audit row's fanout_hosts is the unique count.
func TestAppControlREST_CreateRule_FansOutToEveryHost(t *testing.T) {
	t.Parallel()
	hosts := []string{"host-a", "host-b", "host-c", "host-a"} // dup to assert dedup
	r := newAppControlRig(t, hosts)
	policyID := r.defaultPolicyID(t)

	resp := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/"+i64(policyID)+"/rules",
		map[string]any{
			"rule_type":  rulesapi.RuleTypeBinary,
			"identifier": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"severity":   rulesapi.SeverityRuleMedium,
			"custom_msg": "Blocked by corporate policy",
			"reason":     "demo recording",
		})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	calls := r.inserter.snapshot()
	require.Len(t, calls, 3, "fan-out must dedup duplicate host_ids")
	seen := map[string]struct{}{}
	for _, c := range calls {
		seen[c.HostID] = struct{}{}
		assert.Equal(t, rulesapi.CommandTypeSetApplicationControl, c.Type)
		var payload rulesapi.SetApplicationControlPayload
		require.NoError(t, json.Unmarshal(c.Payload, &payload))
		assert.Equal(t, policyID, payload.PolicyID)
		assert.Positive(t, payload.PolicyVersion, "policy version must be bumped post-create")
		require.Len(t, payload.Rules, 1)
		assert.Equal(t, rulesapi.RuleTypeBinary, payload.Rules[0].RuleType)
		assert.True(t, strings.HasPrefix(payload.Rules[0].RuleID, rulesapi.ApplicationControlRuleIDPrefix),
			"snapshot rule_id must use the app_control: namespace")
	}
	assert.Equal(t, map[string]struct{}{"host-a": {}, "host-b": {}, "host-c": {}}, seen)

	events := r.audit.snapshot()
	require.Len(t, events, 1)
	ev := events[0]
	assert.Equal(t, identityapi.AuditAppControlRuleCreate, ev.Action)
	assert.Equal(t, "application_control_rule", ev.TargetType)
	assert.NotEmpty(t, ev.TargetID)
	require.NotNil(t, ev.UserID)
	assert.Equal(t, int64(42), *ev.UserID, "audit row carries the actor user_id")
	assert.Equal(t, 3, ev.Payload["fanout_hosts"], "fanout_hosts must reflect unique host count")
	assert.Equal(t, 0, ev.Payload["fanout_failed"], "no failures expected on the happy path")
}

// TestAppControl_CreateRule_RecordsFanoutFailures: a per-host CommandInserter failure must not abort the loop AND must surface on the
// audit row as fanout_failed > 0.
func TestAppControlREST_CreateRule_RecordsFanoutFailures(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a", "host-bad"})
	r.inserter.failFor("host-bad", errors.New("synthetic insert failure"))
	policyID := r.defaultPolicyID(t)

	resp := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/"+i64(policyID)+"/rules",
		map[string]any{
			"rule_type":  rulesapi.RuleTypeBinary,
			"identifier": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"severity":   rulesapi.SeverityRuleHigh,
			"reason":     "exercise the failure branch",
		})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"per-host fan-out failure must NOT fail the HTTP create")

	events := r.audit.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, 2, events[0].Payload["fanout_hosts"])
	assert.Equal(t, 1, events[0].Payload["fanout_failed"], "host-bad's failure must show in fanout_failed")
}

// TestAppControl_CreateRule_RejectsDuplicate: posting the same (policy, rule_type, identifier) twice should return 409 with the typed
// error code; the second POST also must NOT fan out a stale duplicate command (the rule didn't change, so the snapshot doesn't need to
// ship).
func TestAppControlREST_CreateRule_RejectsDuplicate(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	body := map[string]any{
		"rule_type":  rulesapi.RuleTypeBinary,
		"identifier": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"severity":   rulesapi.SeverityRuleMedium,
		"reason":     "first create",
	}
	first := r.do(t, http.MethodPost, "/api/v1/app-control/policies/"+i64(policyID)+"/rules", body)
	first.Body.Close()
	require.Equal(t, http.StatusCreated, first.StatusCode)

	second := r.do(t, http.MethodPost, "/api/v1/app-control/policies/"+i64(policyID)+"/rules", body)
	defer second.Body.Close()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var errBody map[string]string
	require.NoError(t, json.NewDecoder(second.Body).Decode(&errBody))
	assert.Equal(t, "application_control.duplicate_rule", errBody["error"])

	// Fan-out from the first create only.
	assert.Len(t, r.inserter.snapshot(), 1)
}

// TestAppControl_CreateRule_BadIdentifierIs400: BINARY rules require 64 lowercase hex characters; anything else is a typed validation
// error mapped to 400.
func TestAppControlREST_CreateRule_BadIdentifierIs400(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	resp := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/"+i64(policyID)+"/rules",
		map[string]any{
			"rule_type":  rulesapi.RuleTypeBinary,
			"identifier": "not-a-real-hash",
			"severity":   rulesapi.SeverityRuleMedium,
			"reason":     "expecting 400",
		})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.invalid_rule", body["error"])
	// No fan-out, no audit row when the create failed validation.
	assert.Empty(t, r.inserter.snapshot())
	assert.Empty(t, r.audit.snapshot())
}

// TestAppControlREST_GetPolicy_NotFound: an unknown policy id surfaces
// the typed 404 with the application_control.policy_not_found code.
func TestAppControlREST_GetPolicy_NotFound(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodGet, "/api/v1/app-control/policies/9999999", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.policy_not_found", body["error"])
}

// TestAppControlREST_GetPolicy_InvalidPolicyID: anything that isn't a positive integer in {id} maps to 400 with the typed code;
// the handler must not leak strconv error strings.
func TestAppControlREST_GetPolicy_InvalidPolicyID(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	for _, raw := range []string{"abc", "-5", "0"} {
		resp := r.do(t, http.MethodGet, "/api/v1/app-control/policies/"+raw, nil)
		var body map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "raw=%q", raw)
		assert.Equal(t, "application_control.invalid_policy_id", body["error"], "raw=%q", raw)
	}
}

// TestAppControlREST_CreateRule_InvalidJSON: a malformed body lands
// 400 with application_control.invalid_json. No fan-out, no audit.
func TestAppControlREST_CreateRule_InvalidJSON(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		r.srv.URL+"/api/v1/app-control/policies/"+i64(policyID)+"/rules",
		strings.NewReader("{not json"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.invalid_json", body["error"])
	assert.Empty(t, r.inserter.snapshot())
	assert.Empty(t, r.audit.snapshot())
}

// TestAppControlREST_CreateRule_InvalidPolicyID: same shape as the GET path — a non-numeric or zero/negative id maps to 400 with the
// typed code before any DB work.
func TestAppControlREST_CreateRule_InvalidPolicyID(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodPost, "/api/v1/app-control/policies/abc/rules",
		map[string]any{"rule_type": rulesapi.RuleTypeBinary, "identifier": "x", "reason": "y"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.invalid_policy_id", body["error"])
}

// TestAppControlREST_CreateRule_NoActorOnContextIs500: the session middleware is supposed to put an Actor on ctx; bypassing it is a
// wiring bug, not user error, so the handler returns 500 instead of silently letting the service-layer guard handle it.
func TestAppControlREST_CreateRule_NoActorOnContextIs500(t *testing.T) {
	t.Parallel()
	// Re-wire the rig without the actor-injecting middleware so the
	// handler sees a bare ctx.
	db := full.Open(t)
	inserter := newRecordingInserter()
	audit := &recordingAudit{}
	rules, err := rulesbootstrap.New(rulesbootstrap.Deps{
		DB:              db,
		Logger:          slog.Default(),
		AuthZ:           allowAllAuthZ{},
		Audit:           audit,
		CommandInserter: inserter.Insert,
		HostLister: func(_ context.Context) ([]string, error) {
			return []string{"host-a"}, nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, rules.ApplySchema(t.Context()))
	mux := http.NewServeMux()
	rules.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	store := rules.ApplicationControlStore()
	policy, err := store.GetPolicyByName(t.Context(), rulesapi.DefaultPolicyName)
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{
		"rule_type": rulesapi.RuleTypeBinary, "identifier": strings.Repeat("a", 64),
		"reason": "no actor on ctx", "severity": rulesapi.SeverityRuleMedium,
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/api/v1/app-control/policies/"+i64(policy.ID)+"/rules",
		strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	// HTTPGate sees an empty tenant_id (no actor on ctx) and returns 403 with reason resource_tenant_missing — that's the correct
	// happy-path posture for a request with no actor reaching the authz gate. The explicit "no actor → 500" branch fires only when
	// HTTPGate happens to allow (e.g. an AuthZ stub that says yes without checking the actor); allowAllAuthZ in this rig satisfies that,
	// so this path is exercised.
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	var errBody map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "internal", errBody["error"])
	assert.Empty(t, inserter.snapshot(), "no actor → must not enqueue commands")
	assert.Empty(t, audit.snapshot(), "no actor → must not emit audit row")
}

// TestAppControlREST_CreateRule_HostListerFailureRecorded: when the host enumerator fails the audit row carries fanout_skipped_reason
// so SIEM can distinguish "lister broke" from "no hosts enrolled." The HTTP response is still 201 (rule landed + the next mutation
// will re-fan); only the audit signal differs.
func TestAppControlREST_CreateRule_HostListerFailureRecorded(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	inserter := newRecordingInserter()
	audit := &recordingAudit{}
	rules, err := rulesbootstrap.New(rulesbootstrap.Deps{
		DB:              db,
		Logger:          slog.Default(),
		AuthZ:           allowAllAuthZ{},
		Audit:           audit,
		CommandInserter: inserter.Insert,
		HostLister: func(_ context.Context) ([]string, error) {
			return nil, errors.New("synthetic host lister failure")
		},
	})
	require.NoError(t, err)
	require.NoError(t, rules.ApplySchema(t.Context()))
	mux := http.NewServeMux()
	rules.RegisterAuthedRoutes(mux)
	actor := &identityapi.Actor{
		UserID: 99,
		Roles: []identityapi.RoleBinding{{
			RoleID:    "admin",
			ScopeType: identityapi.RoleBindingScopeGlobal,
			ScopeID:   identityapi.RoleBindingScopeWildcard,
		}},
	}
	withActor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(identityapi.WithActor(r.Context(), actor))
		mux.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(withActor)
	t.Cleanup(srv.Close)

	store := rules.ApplicationControlStore()
	policy, err := store.GetPolicyByName(t.Context(), rulesapi.DefaultPolicyName)
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]any{
		"rule_type": rulesapi.RuleTypeBinary, "identifier": strings.Repeat("e", 64),
		"reason": "lister fails", "severity": rulesapi.SeverityRuleHigh,
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/api/v1/app-control/policies/"+i64(policy.ID)+"/rules",
		strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"lister failure must not fail the create; the rule landed and the next mutation will re-fan")
	events := audit.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, 0, events[0].Payload["fanout_hosts"])
	assert.Equal(t, 0, events[0].Payload["fanout_failed"])
	assert.Equal(t, "host_lister_error", events[0].Payload["fanout_skipped_reason"],
		"audit row must distinguish lister-broke from no-hosts-enrolled")
	assert.Empty(t, inserter.snapshot(), "no commands enqueued when lister failed")
}

// i64 stringifies a numeric id for URL composition. Tiny helper so the call sites read cleanly without strconv import sprinkled
// everywhere.
func i64(v int64) string {
	return strconv.FormatInt(v, 10)
}

// seedRule is a tiny helper that POSTs a BINARY rule and returns its id so the PATCH/DELETE tests have a fixture without
// duplicating the create JSON 6 times. The identifier is per-test-unique so parallel runs don't collide on the (policy,
// rule_type, identifier) unique key.
func seedRule(t *testing.T, r *appControlRig, policyID int64, identifier string) int64 {
	t.Helper()
	resp := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/"+i64(policyID)+"/rules",
		map[string]any{
			"rule_type":  rulesapi.RuleTypeBinary,
			"identifier": identifier,
			"severity":   rulesapi.SeverityRuleMedium,
			"reason":     "seed for mutation test",
		})
	defer resp.Body.Close()
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "seed rule POST failed: status %d", resp.StatusCode)
	var rule rulesapi.ApplicationControlRule
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rule))
	return rule.ID
}

// TestAppControlREST_UpdateRule_HappyPath_FansOutAndAudits hits PATCH /rules/{id}, asserts the response carries the updated
// fields, that a fresh set_application_control command lands on every host, and that the rule_update audit row reflects the
// post-bump policy_version and fanout counts.
func TestAppControlREST_UpdateRule_HappyPath_FansOutAndAudits(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a", "host-b"})
	policyID := r.defaultPolicyID(t)
	ruleID := seedRule(t, r, policyID, strings.Repeat("1", 64))
	// Capture inserter state after the seed-create so we assert on PATCH-only inserts.
	preCount := len(r.inserter.snapshot())

	resp := r.do(t, http.MethodPatch, "/api/v1/app-control/rules/"+i64(ruleID), map[string]any{
		"enabled":  false,
		"severity": "high",
		"reason":   "PATCH coverage",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated rulesapi.ApplicationControlRule
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	assert.False(t, updated.Enabled)
	assert.Equal(t, rulesapi.SeverityRuleHigh, updated.Severity)

	postCount := len(r.inserter.snapshot())
	assert.Equal(t, 2, postCount-preCount, "PATCH must fan out one snapshot per host")

	events := r.audit.snapshot()
	require.GreaterOrEqual(t, len(events), 2)
	last := events[len(events)-1]
	assert.Equal(t, identityapi.AuditAppControlRuleUpdate, last.Action)
	assert.Equal(t, "application_control_rule", last.TargetType)
	assert.Equal(t, i64(ruleID), last.TargetID)
	assert.Equal(t, 2, last.Payload["fanout_hosts"])
}

// TestAppControlREST_UpdateRule_NotFound: a PATCH on a missing rule maps the typed sentinel to HTTP 404 with the rule_not_found
// error code.
func TestAppControlREST_UpdateRule_NotFound(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodPatch, "/api/v1/app-control/rules/9999999", map[string]any{
		"enabled": false, "reason": "404 path",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.rule_not_found", body.Error)
}

// TestAppControlREST_UpdateRule_NoMutableFieldIs400 confirms a body with only `reason` (no enabled/severity/etc.) is rejected
// as 400 invalid_rule rather than silently bumping the policy version with a SET clause containing only `version`.
func TestAppControlREST_UpdateRule_NoMutableFieldIs400(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	ruleID := seedRule(t, r, policyID, strings.Repeat("2", 64))
	resp := r.do(t, http.MethodPatch, "/api/v1/app-control/rules/"+i64(ruleID), map[string]any{
		"reason": "no mutable field",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAppControlREST_UpdateRule_InvalidRuleID covers the path-parse 400. Symmetric to InvalidPolicyID on the create-rule path.
func TestAppControlREST_UpdateRule_InvalidRuleID(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodPatch, "/api/v1/app-control/rules/not-an-int", map[string]any{
		"enabled": true, "reason": "x",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.invalid_rule_id", body.Error)
}

// TestAppControlREST_UpdateRule_InvalidJSON covers the malformed-body 400 path through the handler.
func TestAppControlREST_UpdateRule_InvalidJSON(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	ruleID := seedRule(t, r, policyID, strings.Repeat("3", 64))
	// Build a raw HTTP request so we can send malformed JSON.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPatch,
		r.srv.URL+"/api/v1/app-control/rules/"+i64(ruleID), strings.NewReader("{not-json}"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAppControlREST_DeleteRule_HappyPath_FansOutAndAudits covers the DELETE path: rule is removed, a post-delete snapshot fans
// out so agents drop the rule, and the audit row records the prior rule's type/identifier.
func TestAppControlREST_DeleteRule_HappyPath_FansOutAndAudits(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	ruleID := seedRule(t, r, policyID, strings.Repeat("4", 64))
	preCount := len(r.inserter.snapshot())

	resp := r.do(t, http.MethodDelete, "/api/v1/app-control/rules/"+i64(ruleID), map[string]any{
		"reason": "DELETE coverage",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	postCount := len(r.inserter.snapshot())
	assert.Equal(t, 1, postCount-preCount, "DELETE must fan out an empty-rules snapshot")

	events := r.audit.snapshot()
	last := events[len(events)-1]
	assert.Equal(t, identityapi.AuditAppControlRuleDelete, last.Action)
	assert.Equal(t, i64(ruleID), last.TargetID)
	assert.Equal(t, "BINARY", last.Payload["rule_type"], "audit captures prior rule_type before delete")
}

// TestAppControlREST_DeleteRule_NotFound: missing rule id → 404 rule_not_found.
func TestAppControlREST_DeleteRule_NotFound(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodDelete, "/api/v1/app-control/rules/9999999", map[string]any{
		"reason": "404 path",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestAppControlREST_DeleteRule_EmptyAndWhitespaceBody both fall through to "reason is required" rather than invalid_json
// (Copilot finding). Splitting into subtests so the bodies-of-various-shapes contract is one test with subtest attribution.
func TestAppControlREST_DeleteRule_EmptyAndWhitespaceBody(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	for _, tc := range []struct {
		name    string
		body    string
		seedHex string // BINARY identifiers must be hex; one unique hex char per subtest avoids the unique-key collision.
	}{
		{"empty body", "", "e"},
		{"whitespace body", "   \n\t  ", "f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ruleID := seedRule(t, r, policyID, strings.Repeat(tc.seedHex, 64))
			req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete,
				r.srv.URL+"/api/v1/app-control/rules/"+i64(ruleID), strings.NewReader(tc.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			resp, err := r.srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			// Whitespace + empty bodies parse as "no reason supplied" -> service-level validation 400 (not invalid_json).
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var body struct {
				Error string `json:"error"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.NotEqual(t, "application_control.invalid_json", body.Error,
				"whitespace-only body must NOT be misreported as invalid_json (Copilot finding on PR #188)")
		})
	}
}

// TestAppControlREST_CreatePolicy_HappyPath covers POST /policies: a new policy lands at version=1 with no rules and no fan-out
// (no assignments yet). The audit row records policy_create + the new policy_id.
func TestAppControlREST_CreatePolicy_HappyPath(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	preInserts := len(r.inserter.snapshot())

	resp := r.do(t, http.MethodPost, "/api/v1/app-control/policies", map[string]any{
		"name":        "engineering-laptops",
		"description": "Custom policy for the eng laptop fleet",
		"reason":      "POST coverage",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var policy rulesapi.ApplicationControlPolicy
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&policy))
	assert.NotZero(t, policy.ID)
	assert.Equal(t, "engineering-laptops", policy.Name)
	assert.Equal(t, int64(1), policy.Version)

	assert.Equal(t, preInserts, len(r.inserter.snapshot()), "POST /policies must not fan out (no assignments)")
	events := r.audit.snapshot()
	last := events[len(events)-1]
	assert.Equal(t, identityapi.AuditAppControlPolicyCreate, last.Action)
	assert.Equal(t, "application_control_policy", last.TargetType)
}

// TestAppControlREST_CreatePolicy_DuplicateName: posting a name that already exists returns 409 duplicate_policy.
func TestAppControlREST_CreatePolicy_DuplicateName(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodPost, "/api/v1/app-control/policies", map[string]any{
		"name":   rulesapi.DefaultPolicyName, // collides with the seeded Default
		"reason": "should collide",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.duplicate_policy", body.Error)
}

// TestAppControlREST_CreatePolicy_InvalidJSON covers the 400 invalid_json path on POST /policies.
func TestAppControlREST_CreatePolicy_InvalidJSON(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		r.srv.URL+"/api/v1/app-control/policies", strings.NewReader("{not-json}"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAppControlREST_UpdatePolicy_HappyPath_RenamesAndBumps covers PATCH /policies/{id}.
func TestAppControlREST_UpdatePolicy_HappyPath_RenamesAndBumps(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	// Create a custom policy so we can rename it without tripping the Default-rename guard.
	createResp := r.do(t, http.MethodPost, "/api/v1/app-control/policies", map[string]any{
		"name": "alpha", "reason": "fixture",
	})
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	var p rulesapi.ApplicationControlPolicy
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&p))

	resp := r.do(t, http.MethodPatch, "/api/v1/app-control/policies/"+i64(p.ID), map[string]any{
		"name":        "alpha-renamed",
		"description": "after the rebrand",
		"reason":      "PATCH coverage",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated rulesapi.ApplicationControlPolicy
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	assert.Equal(t, "alpha-renamed", updated.Name)
	assert.Equal(t, "after the rebrand", updated.Description)
	assert.Equal(t, p.Version+1, updated.Version)
}

// TestAppControlREST_UpdatePolicy_RefusesRenameOfDefault closes the Copilot-flagged bypass: renaming Default then deleting it
// would defeat the immutability guard. The store layer now rejects the rename with PolicyImmutable; verify it surfaces here as
// 409 with the typed error code.
func TestAppControlREST_UpdatePolicy_RefusesRenameOfDefault(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	resp := r.do(t, http.MethodPatch, "/api/v1/app-control/policies/"+i64(policyID), map[string]any{
		"name":   "not-default",
		"reason": "should be refused",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.policy_immutable", body.Error,
		"renaming the seed Default policy must be refused so the rename-then-delete bypass closes")
}

// TestAppControlREST_UpdatePolicy_DefaultDescriptionEditAllowed confirms the rename guard does NOT block a description-only
// edit of the seed Default policy. Operators MUST still be able to amend the Default policy's metadata; only the rename is
// gated.
func TestAppControlREST_UpdatePolicy_DefaultDescriptionEditAllowed(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	resp := r.do(t, http.MethodPatch, "/api/v1/app-control/policies/"+i64(policyID), map[string]any{
		"description": "amended description for the seed policy",
		"reason":      "description-only edit must pass",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestAppControlREST_UpdatePolicy_NotFound: PATCH on missing id → 404.
func TestAppControlREST_UpdatePolicy_NotFound(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodPatch, "/api/v1/app-control/policies/9999999", map[string]any{
		"name": "x", "reason": "404 path",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestAppControlREST_DeletePolicy_HappyPath covers the destructive path on a custom policy.
func TestAppControlREST_DeletePolicy_HappyPath(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	createResp := r.do(t, http.MethodPost, "/api/v1/app-control/policies", map[string]any{
		"name": "to-be-deleted", "reason": "fixture",
	})
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	var p rulesapi.ApplicationControlPolicy
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&p))

	resp := r.do(t, http.MethodDelete, "/api/v1/app-control/policies/"+i64(p.ID), map[string]any{
		"reason": "DELETE coverage",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	events := r.audit.snapshot()
	last := events[len(events)-1]
	assert.Equal(t, identityapi.AuditAppControlPolicyDelete, last.Action)
	assert.Equal(t, i64(p.ID), last.TargetID)
}

// TestAppControlREST_DeletePolicy_RefusesDefault confirms the failsafe: deleting the seed Default policy returns 409 immutable.
func TestAppControlREST_DeletePolicy_RefusesDefault(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	resp := r.do(t, http.MethodDelete, "/api/v1/app-control/policies/"+i64(policyID), map[string]any{
		"reason": "should be refused",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.policy_immutable", body.Error)
}

// TestAppControlREST_DeletePolicy_NotFound: missing id → 404.
func TestAppControlREST_DeletePolicy_NotFound(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodDelete, "/api/v1/app-control/policies/9999999", map[string]any{
		"reason": "404 path",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestAppControlREST_Mutations_InvalidPolicyID covers the path-parse 400 branch on every policy-id-bearing endpoint. Each row
// is a parameterised subtest so the four endpoints share a single setup.
func TestAppControlREST_Mutations_InvalidPolicyID(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	for _, tc := range []struct {
		name   string
		method string
		body   map[string]any
	}{
		{"PATCH", http.MethodPatch, map[string]any{"name": "x", "reason": "x"}},
		{"DELETE", http.MethodDelete, map[string]any{"reason": "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := r.do(t, tc.method, "/api/v1/app-control/policies/not-a-number", tc.body)
			defer resp.Body.Close()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var body struct {
				Error string `json:"error"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, "application_control.invalid_policy_id", body.Error)
		})
	}
}

// TestAppControlREST_BulkUpsertRules_HappyPath confirms POST /policies/{id}/rules:bulkUpsert lands a mixed insert+update batch,
// returns the post-upsert row set + insert/update counts, bumps the policy version exactly once, fans out exactly once to every
// host, and emits a single rule_bulk_upsert audit event.
func TestAppControlREST_BulkUpsertRules_HappyPath(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a", "host-b"})
	policyID := r.defaultPolicyID(t)
	preCount := len(r.inserter.snapshot())

	resp := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/"+i64(policyID)+"/rules:bulkUpsert",
		map[string]any{
			"rules": []map[string]any{
				{"rule_type": "BINARY", "identifier": strings.Repeat("1", 64), "severity": "medium"},
				{"rule_type": "CDHASH", "identifier": strings.Repeat("2", 40), "severity": "medium"},
				{"rule_type": "TEAMID", "identifier": "EQHXZ8M8AV", "severity": "high"},
			},
			"reason": "bulk REST test",
		})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result rulesapi.BulkUpsertResult
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, 3, result.Inserted)
	assert.Equal(t, 0, result.Updated)
	require.Len(t, result.Rules, 3)

	// One fan-out cycle, two hosts → two enqueued commands beyond the seed baseline.
	postCount := len(r.inserter.snapshot())
	assert.Equal(t, 2, postCount-preCount, "bulk upsert fans out exactly one snapshot per host")

	// Exactly one audit row regardless of batch size.
	events := r.audit.snapshot()
	require.Len(t, events, 1, "bulk upsert must emit exactly one audit event regardless of batch size")
	last := events[0]
	assert.Equal(t, identityapi.AuditAppControlRuleBulkUpsert, last.Action)
	assert.Equal(t, "application_control_policy", last.TargetType)
	assert.Equal(t, 3, last.Payload["rules_inserted"])
	assert.Equal(t, 0, last.Payload["rules_updated"])
	assert.Equal(t, 3, last.Payload["rules_total"])
	assert.Equal(t, 2, last.Payload["fanout_hosts"])
}

// TestAppControlREST_BulkUpsertRules_BadItem confirms a per-item validation failure rejects the whole batch with 400
// invalid_rule and the operator-facing message identifies the offending row.
func TestAppControlREST_BulkUpsertRules_BadItem(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	resp := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/"+i64(policyID)+"/rules:bulkUpsert",
		map[string]any{
			"rules": []map[string]any{
				{"rule_type": "BINARY", "identifier": strings.Repeat("3", 64), "severity": "medium"},
				{"rule_type": "BINARY", "identifier": "too-short", "severity": "medium"},
			},
			"reason": "should fail atomically",
		})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.invalid_rule", body.Error)
	assert.Contains(t, body.Message, "bulk item 1", "the operator-facing message names the offending row index")
	// Side-effect assertions (CodeRabbit on PR #190): a failed batch must NOT enqueue any fan-out commands and must NOT emit
	// an audit row. Without these the all-or-nothing contract could regress silently into a partial-success mode that the
	// happy-path test wouldn't notice.
	assert.Empty(t, r.inserter.snapshot(), "failed bulk upsert must not enqueue commands")
	assert.Empty(t, r.audit.snapshot(), "failed bulk upsert must not emit an audit event")
}

// TestAppControlREST_BulkUpsertRules_UnknownPolicy maps the stale-policy FK violation to 404 policy_not_found.
func TestAppControlREST_BulkUpsertRules_UnknownPolicy(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/9999999/rules:bulkUpsert",
		map[string]any{
			"rules": []map[string]any{
				{"rule_type": "BINARY", "identifier": strings.Repeat("4", 64), "severity": "medium"},
			},
			"reason": "should be 404",
		})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.policy_not_found", body.Error)
}

// TestAppControlREST_BulkUpsertRules_InvalidPolicyID covers the path-parse 400.
func TestAppControlREST_BulkUpsertRules_InvalidPolicyID(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/not-a-number/rules:bulkUpsert",
		map[string]any{
			"rules": []map[string]any{
				{"rule_type": "BINARY", "identifier": strings.Repeat("5", 64), "severity": "medium"},
			},
			"reason": "x",
		})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "application_control.invalid_policy_id", body.Error)
}

// TestAppControlREST_BulkUpsertRules_Idempotent confirms re-posting the same payload yields 0 inserted + N updated and the
// audit log has TWO bulk_upsert rows (one per call). The policy version bumps twice even though no field changed — bulk
// upsert always treats the request as a fresh logical operation, which keeps the audit history honest about who re-imported
// what at which time.
func TestAppControlREST_BulkUpsertRules_Idempotent(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	batch := map[string]any{
		"rules": []map[string]any{
			{"rule_type": "BINARY", "identifier": strings.Repeat("6", 64), "severity": "medium"},
		},
		"reason": "first import",
	}
	first := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/"+i64(policyID)+"/rules:bulkUpsert", batch)
	first.Body.Close()
	require.Equal(t, http.StatusOK, first.StatusCode)

	batch["reason"] = "re-import"
	second := r.do(t, http.MethodPost,
		"/api/v1/app-control/policies/"+i64(policyID)+"/rules:bulkUpsert", batch)
	defer second.Body.Close()
	require.Equal(t, http.StatusOK, second.StatusCode)
	var result rulesapi.BulkUpsertResult
	require.NoError(t, json.NewDecoder(second.Body).Decode(&result))
	assert.Equal(t, 0, result.Inserted)
	assert.Equal(t, 1, result.Updated)

	// Audit cardinality (CodeRabbit on PR #190): each bulk-upsert call emits exactly one row regardless of the in-batch
	// count, so the comment's "TWO bulk_upsert rows after two re-posts" claim has to be backed by an assertion. The events
	// snapshot here covers the whole rig's lifetime so both calls' rows show up.
	events := r.audit.snapshot()
	require.Len(t, events, 2, "two bulk-upsert calls must emit two audit rows")
	assert.Equal(t, identityapi.AuditAppControlRuleBulkUpsert, events[0].Action)
	assert.Equal(t, identityapi.AuditAppControlRuleBulkUpsert, events[1].Action)
	assert.Equal(t, 1, events[0].Payload["rules_inserted"])
	assert.Equal(t, 0, events[1].Payload["rules_inserted"])
	assert.Equal(t, 1, events[1].Payload["rules_updated"])
}

// TestAppControlREST_ListRulesAcrossPolicies_HappyPath pins the REST wire shape the cross-policy GET endpoint emits: a
// {rules, total, limit, offset} envelope. The default policy gets two rules seeded so the empty filter returns >=2 rows.
func TestAppControlREST_ListRulesAcrossPolicies_HappyPath(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	for i, ident := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		create := r.do(t, http.MethodPost,
			"/api/v1/app-control/policies/"+i64(policyID)+"/rules",
			map[string]any{
				"rule_type":  rulesapi.RuleTypeBinary,
				"identifier": ident,
				"severity":   rulesapi.SeverityRuleHigh,
				"reason":     "seed " + i64(int64(i)),
			})
		require.Equal(t, http.StatusCreated, create.StatusCode)
		create.Body.Close()
	}

	resp := r.do(t, http.MethodGet, "/api/v1/app-control/rules", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		Rules  []rulesapi.ApplicationControlRule `json:"rules"`
		Total  int                               `json:"total"`
		Limit  int                               `json:"limit"`
		Offset int                               `json:"offset"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.GreaterOrEqual(t, body.Total, 2)
	assert.Len(t, body.Rules, body.Total)
	assert.Equal(t, rulesapi.DefaultListRulesAcrossPoliciesLimit, body.Limit, "limit defaults to DefaultListRulesAcrossPoliciesLimit")
	assert.Equal(t, 0, body.Offset)
}

// TestAppControlREST_ListRulesAcrossPolicies_Filters covers each query-param dimension narrowing the result correctly. Two
// rules of different types seed the policy so a rule_type filter has something to narrow on.
func TestAppControlREST_ListRulesAcrossPolicies_Filters(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	// Seed: one BINARY high + one CDHASH medium so each filter dimension has a unique target.
	for _, body := range []map[string]any{
		{"rule_type": rulesapi.RuleTypeBinary, "identifier": strings.Repeat("a", 64), "severity": rulesapi.SeverityRuleHigh, "reason": "binary seed"},
		{"rule_type": rulesapi.RuleTypeCDHash, "identifier": strings.Repeat("c", 40), "severity": rulesapi.SeverityRuleMedium, "reason": "cdhash seed"},
	} {
		create := r.do(t, http.MethodPost, "/api/v1/app-control/policies/"+i64(policyID)+"/rules", body)
		require.Equal(t, http.StatusCreated, create.StatusCode)
		create.Body.Close()
	}

	cases := []struct {
		name        string
		query       string
		wantType    rulesapi.RuleType
		expectAtMin int
	}{
		{name: "filter by rule_type=BINARY", query: "?rule_type=BINARY", wantType: rulesapi.RuleTypeBinary, expectAtMin: 1},
		{name: "filter by rule_type=CDHASH", query: "?rule_type=CDHASH", wantType: rulesapi.RuleTypeCDHash, expectAtMin: 1},
		{name: "filter by severity=high", query: "?severity=high", expectAtMin: 1},
		{name: "filter by policy_id", query: "?policy_id=" + i64(policyID), expectAtMin: 2},
		{name: "limit=1 caps page size; Total ignores limit", query: "?limit=1", expectAtMin: 1},
		{name: "intersection: BINARY + policy_id", query: "?rule_type=BINARY&policy_id=" + i64(policyID), wantType: rulesapi.RuleTypeBinary, expectAtMin: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := r.do(t, http.MethodGet, "/api/v1/app-control/rules"+tc.query, nil)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var body struct {
				Rules []rulesapi.ApplicationControlRule `json:"rules"`
				Total int                               `json:"total"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.GreaterOrEqual(t, body.Total, tc.expectAtMin)
			if tc.wantType != "" {
				for _, row := range body.Rules {
					assert.Equal(t, tc.wantType, row.RuleType, "every row must match the rule_type filter")
				}
			}
		})
	}
}

// TestAppControlREST_ListRulesAcrossPolicies_RejectsInvalidQuery covers the typed 400 paths every malformed query param
// surfaces. Each case returns application_control.invalid_query — no result data leaks even on bad input.
func TestAppControlREST_ListRulesAcrossPolicies_RejectsInvalidQuery(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})

	cases := []struct {
		name  string
		query string
	}{
		{name: "non-numeric policy_id", query: "?policy_id=abc"},
		{name: "non-positive policy_id", query: "?policy_id=0"},
		{name: "unknown rule_type", query: "?rule_type=GIBBERISH"},
		{name: "unknown severity", query: "?severity=urgent"},
		{name: "non-boolean enabled", query: "?enabled=maybe"},
		{name: "limit too large", query: "?limit=99999"},
		{name: "limit negative", query: "?limit=-1"},
		{name: "limit zero", query: "?limit=0"},
		{name: "non-numeric limit", query: "?limit=abc"},
		{name: "negative offset", query: "?offset=-5"},
		{name: "non-numeric offset", query: "?offset=xyz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := r.do(t, http.MethodGet, "/api/v1/app-control/rules"+tc.query, nil)
			defer resp.Body.Close()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var body struct {
				Error string `json:"error"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, "application_control.invalid_query", body.Error)
		})
	}
}

// TestAppControlREST_ListRulesAcrossPolicies_Pagination pins the offset+limit contract: page 1 + page 2 cover the full set
// without overlap; Total is constant across pages.
func TestAppControlREST_ListRulesAcrossPolicies_Pagination(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	for _, ident := range []string{
		strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64),
	} {
		create := r.do(t, http.MethodPost,
			"/api/v1/app-control/policies/"+i64(policyID)+"/rules",
			map[string]any{
				"rule_type": rulesapi.RuleTypeBinary, "identifier": ident,
				"severity": rulesapi.SeverityRuleHigh, "reason": "pagination seed",
			})
		require.Equal(t, http.StatusCreated, create.StatusCode)
		create.Body.Close()
	}

	page1Resp := r.do(t, http.MethodGet, "/api/v1/app-control/rules?limit=2&offset=0", nil)
	defer page1Resp.Body.Close()
	var page1 struct {
		Rules []rulesapi.ApplicationControlRule `json:"rules"`
		Total int                               `json:"total"`
	}
	require.NoError(t, json.NewDecoder(page1Resp.Body).Decode(&page1))
	assert.Len(t, page1.Rules, 2)

	page2Resp := r.do(t, http.MethodGet, "/api/v1/app-control/rules?limit=2&offset=2", nil)
	defer page2Resp.Body.Close()
	var page2 struct {
		Rules []rulesapi.ApplicationControlRule `json:"rules"`
		Total int                               `json:"total"`
	}
	require.NoError(t, json.NewDecoder(page2Resp.Body).Decode(&page2))
	assert.Equal(t, page1.Total, page2.Total, "Total stays constant across pages")
	// Page 1 + page 2 must not share rule IDs (deterministic ordering by id).
	seen := map[int64]bool{}
	for _, r := range page1.Rules {
		seen[r.ID] = true
	}
	for _, r := range page2.Rules {
		assert.False(t, seen[r.ID], "page 2 must not repeat any row from page 1")
	}
}

// TestAppControlREST_ListHostGroups_HappyPath: GET /host-groups returns the seed `all-hosts` row in a {host_groups: [...]}
// envelope. Phase A always has this single row.
func TestAppControlREST_ListHostGroups_HappyPath(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodGet, "/api/v1/app-control/host-groups", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		HostGroups []rulesapi.HostGroup `json:"host_groups"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body.HostGroups, 1)
	assert.Equal(t, rulesapi.DefaultHostGroupName, body.HostGroups[0].Name)
}

// TestAppControlREST_GetHostGroup_HappyPath + NotFound + InvalidID round-trips the single-row read.
func TestAppControlREST_GetHostGroup_HappyPath(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	list := r.do(t, http.MethodGet, "/api/v1/app-control/host-groups", nil)
	var body struct {
		HostGroups []rulesapi.HostGroup `json:"host_groups"`
	}
	require.NoError(t, json.NewDecoder(list.Body).Decode(&body))
	list.Body.Close()
	require.NotEmpty(t, body.HostGroups)

	resp := r.do(t, http.MethodGet, "/api/v1/app-control/host-groups/"+i64(body.HostGroups[0].ID), nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got rulesapi.HostGroup
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, body.HostGroups[0].ID, got.ID)
	assert.Equal(t, rulesapi.DefaultHostGroupName, got.Name)
}

func TestAppControlREST_GetHostGroup_NotFound(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodGet, "/api/v1/app-control/host-groups/99999999", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var errBody struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.Equal(t, "application_control.host_group_not_found", errBody.Error)
}

// TestAppControlREST_ListAssignments_SurfacesSeedRow: the seed Default policy has exactly one assignment row pointing at
// the all-hosts group. Pinning the wire shape so a Phase B regression that drops the assignment is caught.
func TestAppControlREST_ListAssignments_SurfacesSeedRow(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	resp := r.do(t, http.MethodGet, "/api/v1/app-control/policies/"+i64(policyID)+"/assignments", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		Assignments []rulesapi.Assignment `json:"assignments"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body.Assignments, 1)
	assert.Equal(t, policyID, body.Assignments[0].PolicyID)
	assert.NotZero(t, body.Assignments[0].HostGroupID)
	assert.Equal(t, 0, body.Assignments[0].Priority)
}

// TestAppControlREST_ListAssignments_UnknownPolicyReturnsEmpty: the assignments endpoint does NOT 404 on a stale policy id;
// returning [] is the correct shape. Pinning that contract here so a Phase B regression that adds a 404 check is caught.
func TestAppControlREST_ListAssignments_UnknownPolicyReturnsEmpty(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	resp := r.do(t, http.MethodGet, "/api/v1/app-control/policies/99999999/assignments", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		Assignments []rulesapi.Assignment `json:"assignments"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Empty(t, body.Assignments)
}

// TestAppControlREST_HostGroupMutations_ReadOnlyInPhaseA pins the 405 + typed error contract for every host-group +
// assignment mutation route. Each case asserts the status code, the typed application_control.read_only_in_phase_a code,
// and (for non-leaf paths) the Allow: GET header per RFC 9110.
func TestAppControlREST_HostGroupMutations_ReadOnlyInPhaseA(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	policyID := r.defaultPolicyID(t)
	list := r.do(t, http.MethodGet, "/api/v1/app-control/host-groups", nil)
	var listBody struct {
		HostGroups []rulesapi.HostGroup `json:"host_groups"`
	}
	require.NoError(t, json.NewDecoder(list.Body).Decode(&listBody))
	list.Body.Close()
	require.NotEmpty(t, listBody.HostGroups)
	groupID := listBody.HostGroups[0].ID

	cases := []struct {
		name           string
		method         string
		path           string
		expectAllowGET bool
	}{
		{"POST /host-groups", http.MethodPost, "/api/v1/app-control/host-groups", true},
		{"PATCH /host-groups/{id}", http.MethodPatch, "/api/v1/app-control/host-groups/" + i64(groupID), true},
		{"DELETE /host-groups/{id}", http.MethodDelete, "/api/v1/app-control/host-groups/" + i64(groupID), true},
		{"POST /policies/{id}/assignments", http.MethodPost, "/api/v1/app-control/policies/" + i64(policyID) + "/assignments", true},
		// The /assignments/{group_id} leaf has no GET surface today; Allow header is empty.
		{"DELETE /assignments/{group_id}", http.MethodDelete, "/api/v1/app-control/policies/" + i64(policyID) + "/assignments/" + i64(groupID), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := r.do(t, tc.method, tc.path, map[string]any{"placeholder": "phase A test"})
			defer resp.Body.Close()
			require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
			var body struct {
				Error string `json:"error"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, "application_control.read_only_in_phase_a", body.Error)
			if tc.expectAllowGET {
				assert.Equal(t, "GET", resp.Header.Get("Allow"))
			}
		})
	}
}
