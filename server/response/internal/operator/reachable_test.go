package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
)

// fakeReachable records what the handler asked of the service and answers with set values.
type fakeReachable struct {
	set       api.ReachableSet
	err       error
	calls     []string
	actor     identityapi.PrincipalRef
	addresses []api.ReachableAddress
	reason    string
	expected  *int64
}

func (f *fakeReachable) Get(context.Context) (api.ReachableSet, error) {
	f.calls = append(f.calls, "get")
	return f.set, f.err
}

func (f *fakeReachable) Replace(_ context.Context, actor identityapi.PrincipalRef, _ string,
	addresses []api.ReachableAddress, reason string, expected *int64) (api.ReachableSet, error) {
	f.calls = append(f.calls, "replace")
	f.actor, f.addresses, f.reason, f.expected = actor, addresses, reason, expected
	return f.set, f.err
}

func serveReachable(t *testing.T, svc ReachableService, authz identityapi.AuthZ, method, body string) *http.Response {
	t.Helper()
	mux := http.NewServeMux()
	NewReachableHandler(svc, authz, slog.Default()).RegisterRoutes(mux)
	actor := &identityapi.Actor{Principal: identityapi.PrincipalRef{ID: "user:7", Type: "user"}}
	withActor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(identityapi.WithActor(r.Context(), actor)))
	})
	srv := httptest.NewServer(withActor)
	t.Cleanup(srv.Close)
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+"/api/v1/containment/reachable-addresses",
		strings.NewReader(body))
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// The chokepoint gates both routes, and the write is a DIFFERENT action from the read: an operator who may see what stays reachable
// is not thereby allowed to widen it.
//
// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/editing-the-set-is-its-own-permission
func TestReachableHandler_Authorizes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc       string
		method     string
		body       string
		wantAction identityapi.Action
	}{
		{desc: "reading", method: http.MethodGet, wantAction: identityapi.ActionContainmentConfigRead},
		{
			desc:       "replacing",
			method:     http.MethodPut,
			body:       `{"addresses":[{"cidr":"192.0.2.7"}],"reason":"why"}`,
			wantAction: identityapi.ActionContainmentConfigWrite,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc+" is refused without the action", func(t *testing.T) {
			t.Parallel()
			svc := &fakeReachable{}
			authz := &recordingAuthZ{allow: false}
			resp := serveReachable(t, svc, authz, tc.method, tc.body)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			assert.Equal(t, []string{string(tc.wantAction) + " containment_config:"}, authz.decisions)
			// Gated BEFORE the body is read, so a caller without the action learns nothing about whether their request was valid.
			assert.Empty(t, svc.calls)
		})
		t.Run(tc.desc+" is allowed with it", func(t *testing.T) {
			t.Parallel()
			svc := &fakeReachable{}
			resp := serveReachable(t, svc, &recordingAuthZ{allow: true}, tc.method, tc.body)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.NotEmpty(t, svc.calls)
		})
	}
}

func TestReachableHandler_PassesTheRequestThrough(t *testing.T) {
	t.Parallel()
	svc := &fakeReachable{set: api.ReachableSet{Version: 4}}
	expected := int64(3)
	body := fmt.Sprintf(`{"addresses":[{"cidr":"192.0.2.7","port":443,"transport":"tcp","note":"MDM"}],"reason":"why",
		"expected_version":%d}`, expected)
	resp := serveReachable(t, svc, &recordingAuthZ{allow: true}, http.MethodPut, body)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []api.ReachableAddress{{CIDR: "192.0.2.7", Port: 443, Transport: "tcp", Note: "MDM"}}, svc.addresses)
	assert.Equal(t, "why", svc.reason)
	assert.Equal(t, identityapi.PrincipalRef{ID: "user:7", Type: "user"}, svc.actor)
	require.NotNil(t, svc.expected,
		"the version the operator edited against must reach the service, or their edit lands on a set they never saw")
	assert.Equal(t, expected, *svc.expected)

	var got api.ReachableSet
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &got), string(raw))
	assert.Equal(t, int64(4), got.Version)
}

// A request that names no version is asking for the set whatever it holds, which is what a scripted caller does. Distinguished from
// a version of zero, which names the seeded set.
func TestReachableHandler_DistinguishesAnAbsentVersionFromZero(t *testing.T) {
	t.Parallel()
	svc := &fakeReachable{}
	absent := serveReachable(t, svc, &recordingAuthZ{allow: true}, http.MethodPut, `{"addresses":[],"reason":"why"}`)
	defer absent.Body.Close()
	assert.Nil(t, svc.expected)

	svc = &fakeReachable{}
	zero := serveReachable(t, svc, &recordingAuthZ{allow: true}, http.MethodPut, `{"addresses":[],"reason":"why","expected_version":0}`)
	defer zero.Body.Close()
	require.NotNil(t, svc.expected)
	assert.Equal(t, int64(0), *svc.expected)
}

// Every refusal the service can return has its own code and status, so the console can say which address to fix rather than that
// the set was invalid. A refusal answered as a 500 would also tell the operator to retry something that will never work.
//
// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/an-address-that-would-undo-containment-is-refused
func TestReachableHandler_ReportsEachRefusal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{api.ErrReachableVersionConflict, http.StatusConflict, "version_conflict"},
		{api.ErrReachableReasonRequired, http.StatusBadRequest, "reason_required"},
		{api.ErrReachableReasonTooLong, http.StatusBadRequest, "reason_too_long"},
		{api.ErrReachableTooMany, http.StatusBadRequest, "too_many_addresses"},
		{api.ErrReachableInvalidCIDR, http.StatusBadRequest, "invalid_address"},
		{api.ErrReachableTooBroad, http.StatusBadRequest, "address_too_broad"},
		{api.ErrReachableInvalidPort, http.StatusBadRequest, "invalid_port"},
		{api.ErrReachableInvalidTransport, http.StatusBadRequest, "invalid_transport"},
		{api.ErrReachableNoteTooLong, http.StatusBadRequest, "note_too_long"},
		{api.ErrReachableDuplicate, http.StatusBadRequest, "duplicate_address"},
	}
	for _, tc := range cases {
		t.Run(tc.wantCode, func(t *testing.T) {
			t.Parallel()
			// Wrapped, as the service wraps it with which entry was wrong: the handler matches on errors.Is, not on equality.
			svc := &fakeReachable{err: fmt.Errorf("address 2 (%q): %w", "0.0.0.0/0", tc.err)}
			resp := serveReachable(t, svc, &recordingAuthZ{allow: true}, http.MethodPut, `{"addresses":[],"reason":"why"}`)
			defer resp.Body.Close()

			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			raw, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			var body struct {
				Error   string `json:"error"`
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(raw, &body), string(raw))
			assert.Equal(t, tc.wantCode, body.Error)
			assert.Contains(t, body.Message, "address 2", "the operator is told which entry, not just that the set was refused")
		})
	}
}

// A body with no address list is a malformed request, not a request to clear the set. The difference matters more here than it
// usually does: decoding an absent list into an empty slice would cut every contained host back to the bare lifeline, which is the
// opposite of what a caller who misspelled a field wanted. Clearing stays available, spelled explicitly.
func TestReachableHandler_WillNotClearTheSetByOmission(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"reason":"why"}`,
		`{"reason":"why","addresses":null}`,
		`{"reason":"why","address":[{"cidr":"192.0.2.7"}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			svc := &fakeReachable{}
			resp := serveReachable(t, svc, &recordingAuthZ{allow: true}, http.MethodPut, body)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "bad_body", errorCode(t, resp))
			assert.Empty(t, svc.calls, "nothing reached the service, so nothing could have been cleared")
		})
	}

	// And the explicit spelling still clears it. Its own subtest, because this test is parallel and its subtests outlive its body,
	// so a response closed here would be closed before they ran.
	t.Run("an explicit empty list still clears the set", func(t *testing.T) {
		t.Parallel()
		svc := &fakeReachable{}
		resp := serveReachable(t, svc, &recordingAuthZ{allow: true}, http.MethodPut, `{"reason":"done","addresses":[]}`)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, []string{"replace"}, svc.calls)
		assert.Empty(t, svc.addresses)
	})
}

func TestReachableHandler_RefusesABodyThatIsNotASet(t *testing.T) {
	t.Parallel()
	svc := &fakeReachable{}
	resp := serveReachable(t, svc, &recordingAuthZ{allow: true}, http.MethodPut, `{"addresses":"everything"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "bad_body", errorCode(t, resp))
	assert.Empty(t, svc.calls)

	// Over the cap, which is itself above the largest set the validator would accept, so this is a body that is not the shape the
	// route serves rather than a legitimate maximum one.
	oversized := `{"reason":"why","addresses":[` + strings.Repeat(`{"cidr":"192.0.2.7","note":"`+strings.Repeat("x", 4000)+`"},`, 100) +
		`{"cidr":"192.0.2.8"}]}`
	resp = serveReachable(t, svc, &recordingAuthZ{allow: true}, http.MethodPut, oversized)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	assert.Equal(t, "body_too_large", errorCode(t, resp))
	assert.Empty(t, svc.calls, "a body over the cap is refused without being decoded")
}
