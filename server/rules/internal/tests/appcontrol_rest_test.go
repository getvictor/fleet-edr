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
