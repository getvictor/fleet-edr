//go:build integration

// Per-context integration tests for the rules bounded context.
// Exercise the full bootstrap.New -> ApplySchema -> Service stack
// against a real MySQL. Skips when EDR_TEST_DSN isn't set, matching
// the project's other DB-using test files.
//
// Per docs/adr/0004-modular-monolith-bounded-contexts.md.

package tests

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	"github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

const testEnrollSecret = "rules-integration-secret"

// recordingCommandInserter captures every fan-out closure call so the
// test can assert on the per-host command payloads. Goroutine-safe so
// the tests can run with -race.
type recordingCommandInserter struct {
	mu     sync.Mutex
	calls  []recordedCommand
	nextID int64
}

type recordedCommand struct {
	HostID      string
	CommandType string
	Payload     []byte
}

func (r *recordingCommandInserter) Insert(_ context.Context, hostID, commandType string, payload []byte) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	r.calls = append(r.calls, recordedCommand{HostID: hostID, CommandType: commandType, Payload: append([]byte(nil), payload...)})
	return r.nextID, nil
}

func (r *recordingCommandInserter) snapshot() []recordedCommand {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedCommand, len(r.calls))
	copy(out, r.calls)
	return out
}

// newRules wires rules.bootstrap.New against a fresh test DB. ep may
// be nil for tests that don't exercise the fan-out path; the closure
// is wired to call ep.Service().ActiveHostIDs at request time.
func newRules(t *testing.T, ep **endpointbootstrap.Endpoint, cmds *recordingCommandInserter) *rulesbootstrap.Rules {
	t.Helper()
	s := full.Open(t)
	deps := rulesbootstrap.Deps{
		DB:     s,
		Logger: slog.Default(),
	}
	if ep != nil && cmds != nil {
		deps.ActiveHostsLister = func(ctx context.Context) ([]string, error) {
			return (*ep).Service().ActiveHostIDs(ctx)
		}
		deps.CommandInserter = cmds.Insert
	}
	r, err := rulesbootstrap.New(deps)
	require.NoError(t, err)
	require.NoError(t, r.ApplySchema(t.Context()))
	return r
}

// TestPolicy_GetSeed confirms a fresh DB has the default policy with
// version 1 and an empty blocklist.
func TestPolicy_GetSeed(t *testing.T) {
	r := newRules(t, nil, nil)
	p, err := r.PolicyService().Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, api.DefaultPolicyName, p.Name)
	assert.Equal(t, int64(1), p.Version)
	assert.Empty(t, p.Blocklist.Paths)
	assert.Empty(t, p.Blocklist.Hashes)
	assert.Equal(t, "system", p.UpdatedBy)
}

// TestPolicy_UpdateBumpsVersion locks the bump-and-persist semantics.
func TestPolicy_UpdateBumpsVersion(t *testing.T) {
	r := newRules(t, nil, nil)
	updated, err := r.PolicyService().Update(t.Context(), api.UpdateRequest{
		Paths:  []string{"/private/tmp/bad"},
		Hashes: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Actor:  "qa-tester",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.Version)
	assert.Equal(t, "qa-tester", updated.UpdatedBy)
	assert.Equal(t, []string{"/private/tmp/bad"}, updated.Blocklist.Paths)
}

// TestPolicy_UpdateValidation surfaces validation errors as the
// public sentinels callers can errors.Is.
func TestPolicy_UpdateValidation(t *testing.T) {
	r := newRules(t, nil, nil)

	_, err := r.PolicyService().Update(t.Context(), api.UpdateRequest{
		Paths: []string{"relative/path"},
		Actor: "qa-tester",
	})
	require.ErrorIs(t, err, api.ErrInvalidPath)

	_, err = r.PolicyService().Update(t.Context(), api.UpdateRequest{
		Hashes: []string{"deadbeef"},
		Actor:  "qa-tester",
	})
	require.ErrorIs(t, err, api.ErrInvalidHash)
}

// TestPolicy_ActiveCommandPayload_Empty asserts the hasContent=false
// signal endpoint's enroll fan-out depends on.
func TestPolicy_ActiveCommandPayload_Empty(t *testing.T) {
	r := newRules(t, nil, nil)
	payload, version, hasContent, err := r.PolicyService().ActiveCommandPayload(t.Context())
	require.NoError(t, err)
	assert.False(t, hasContent)
	assert.Nil(t, payload)
	assert.Equal(t, int64(1), version)
}

// TestPolicy_ActiveCommandPayload_NonEmpty round-trips a non-empty
// blocklist to its set_blocklist command bytes.
func TestPolicy_ActiveCommandPayload_NonEmpty(t *testing.T) {
	r := newRules(t, nil, nil)
	updated, err := r.PolicyService().Update(t.Context(), api.UpdateRequest{
		Paths: []string{"/private/tmp/bad"},
		Actor: "qa-tester",
	})
	require.NoError(t, err)

	payload, version, hasContent, err := r.PolicyService().ActiveCommandPayload(t.Context())
	require.NoError(t, err)
	assert.True(t, hasContent)
	assert.Equal(t, updated.Version, version)

	var got api.SetBlocklistPayload
	require.NoError(t, json.Unmarshal(payload, &got))
	assert.Equal(t, api.DefaultPolicyName, got.Name)
	assert.Equal(t, updated.Version, got.Version)
	assert.Equal(t, []string{"/private/tmp/bad"}, got.Paths)
	assert.Empty(t, got.Hashes)
}

// TestCatalog_ListShape locks in registration order + documentation
// completeness for every shipped rule.
func TestCatalog_ListShape(t *testing.T) {
	r := newRules(t, nil, nil)
	catalog := r.Catalog().List()
	require.Len(t, catalog, 8)
	wantIDs := []string{
		"suspicious_exec",
		"persistence_launchagent",
		"dyld_insert",
		"shell_from_office",
		"osascript_network_exec",
		"credential_keychain_dump",
		"privilege_launchd_plist_write",
		"sudoers_tamper",
	}
	for i, want := range wantIDs {
		assert.Equal(t, want, catalog[i].ID, "rule at index %d", i)
		assert.NotEmpty(t, catalog[i].Doc.Title, "rule %s missing Doc.Title", catalog[i].ID)
		assert.NotEmpty(t, catalog[i].Doc.Severity, "rule %s missing Doc.Severity", catalog[i].ID)
	}
}

// TestContentService_ActiveRules surfaces the same eight rules through
// the engine-facing interface.
func TestContentService_ActiveRules(t *testing.T) {
	r := newRules(t, nil, nil)
	rules := r.ContentService().ActiveRules()
	require.Len(t, rules, 8)
	for _, rule := range rules {
		assert.NotEmpty(t, rule.ID())
		assert.NotEmpty(t, rule.Doc().Title)
	}
}

// TestOperator_PutPolicyFanout wires endpoint + rules together,
// enrolls hosts, PUTs a policy via the operator handler, and asserts
// each enrolled host received a set_blocklist command. End-to-end
// coverage of the late-binding closure pattern in cmd/main.
func TestOperator_PutPolicyFanout(t *testing.T) {
	cmds := &recordingCommandInserter{}
	var ep *endpointbootstrap.Endpoint

	// Single shared DB across rulesCtx + endpointCtx so the bidirectional
	// dependency in cmd/main is exercised end-to-end.
	s := full.Open(t)
	rulesCtx, err := rulesbootstrap.New(rulesbootstrap.Deps{
		DB:     s,
		Logger: slog.Default(),
		ActiveHostsLister: func(ctx context.Context) ([]string, error) {
			return ep.Service().ActiveHostIDs(ctx)
		},
		CommandInserter: cmds.Insert,
	})
	require.NoError(t, err)
	require.NoError(t, rulesCtx.ApplySchema(t.Context()))

	ep, err = endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  s,
		Logger:              slog.Default(),
		EnrollSecret:        testEnrollSecret,
		EnrollRatePerMinute: 600,
	})
	require.NoError(t, err)
	require.NoError(t, ep.ApplySchema(t.Context()))

	ctx := t.Context()
	for _, hostID := range []string{
		"AAAAAAAA-1111-1111-1111-111111111111",
		"BBBBBBBB-2222-2222-2222-222222222222",
	} {
		_, err := ep.Service().Enroll(ctx, endpointapi.EnrollRequest{
			EnrollSecret: testEnrollSecret,
			HardwareUUID: hostID,
			Hostname:     "h",
			OSVersion:    "macOS 14",
			AgentVersion: "test",
		}, "127.0.0.1")
		require.NoError(t, err)
	}

	mux := http.NewServeMux()
	rulesCtx.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := strings.NewReader(`{
        "paths":["/private/tmp/blocked"],
        "actor":"qa-tester",
        "reason":"integration test"
    }`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, srv.URL+"/api/policy", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got api.BlocklistPolicy
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, int64(2), got.Version)

	calls := cmds.snapshot()
	require.Len(t, calls, 2, "fan-out must hit every enrolled host exactly once")
	for _, call := range calls {
		assert.Equal(t, api.CommandTypeSetBlocklist, call.CommandType)
		var payload api.SetBlocklistPayload
		require.NoError(t, json.Unmarshal(call.Payload, &payload))
		assert.Equal(t, int64(2), payload.Version)
		assert.Equal(t, []string{"/private/tmp/blocked"}, payload.Paths)
	}
}

// TestOperator_GetRules locks the JSON shape of GET /api/rules so
// the UI's RuleDetail.tsx + tools/gen-rule-docs both keep working.
func TestOperator_GetRules(t *testing.T) {
	r := newRules(t, nil, nil)
	mux := http.NewServeMux()
	r.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/rules", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Rules []struct {
			ID  string `json:"id"`
			Doc struct {
				Title    string `json:"title"`
				Severity string `json:"severity"`
			} `json:"doc"`
		} `json:"rules"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body.Rules, 8)
	assert.Equal(t, "suspicious_exec", body.Rules[0].ID)
	assert.NotEmpty(t, body.Rules[0].Doc.Title)
}

// TestOperator_GetAttackCoverage asserts navigator-layer JSON is
// byte-identical across requests (snapshot-friendly).
func TestOperator_GetAttackCoverage(t *testing.T) {
	r := newRules(t, nil, nil)
	mux := http.NewServeMux()
	r.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	fetch := func() string {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/attack-coverage", nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "enterprise-attack", body["domain"])
		out, err := json.Marshal(body)
		require.NoError(t, err)
		return string(out)
	}
	first := fetch()
	for range 3 {
		assert.Equal(t, first, fetch(), "Navigator layer must be byte-identical across requests")
	}
}

// TestBootstrap_MissingDeps surfaces required-field errors.
func TestBootstrap_MissingDeps(t *testing.T) {
	t.Run("nil DB", func(t *testing.T) {
		_, err := rulesbootstrap.New(rulesbootstrap.Deps{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DB")
	})

	t.Run("asymmetric ActiveHostsLister and CommandInserter", func(t *testing.T) {
		s := full.Open(t)
		_, err := rulesbootstrap.New(rulesbootstrap.Deps{
			DB: s,
			ActiveHostsLister: func(context.Context) ([]string, error) {
				return nil, errors.New("unused")
			},
			// CommandInserter intentionally nil
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "set together")
	})
}
