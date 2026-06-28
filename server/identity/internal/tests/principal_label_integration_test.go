package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/serviceaccounts"
)

// TestPrincipalLabel_resolvesEachPrincipalType pins the read-side label resolution the detection-config exclusions list relies on: a
// user principal resolves to its live email, a service-account principal to its live name, the system principal to "system", and an
// unresolvable / malformed id to "" (so the UI falls back to the raw principal identifier). See ADR-0017.
func TestPrincipalLabel_resolvesEachPrincipalType(t *testing.T) {
	t.Parallel()
	id, db := newServiceAccountIdentity(t)
	svc := id.Service()
	uid := seedUser(t, db, "author@itest.local")

	// Create a service account through the admin API so its row + name exist exactly as the resolver will read them.
	authed := http.NewServeMux()
	id.RegisterAuthedRoutes(authed)
	createBody, _ := json.Marshal(map[string]any{"name": "ci-bot", "role": "analyst"})
	cw := httptest.NewRecorder()
	authed.ServeHTTP(cw, superAdminReq(httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/settings/service-accounts", strings.NewReader(string(createBody))), uid))
	require.Equal(t, http.StatusCreated, cw.Code, "body: %s", cw.Body.String())
	var created struct {
		ID int64 `json:"id"`
	}
	require.NoError(t, json.Unmarshal(cw.Body.Bytes(), &created))

	cases := []struct {
		name        string
		principalID string
		want        string
		wantErr     error
	}{
		{name: "user resolves to email", principalID: api.UserPrincipalID(uid), want: "author@itest.local"},
		{name: "service account resolves to name", principalID: api.ServiceAccountPrincipalID(created.ID), want: "ci-bot"},
		{name: "system principal resolves to system", principalID: api.PrincipalSystemID, want: "system"},
		{name: "unknown prefix yields empty, no error", principalID: "bogus_1", want: ""},
		// A deleted author surfaces ErrUserNotFound (an empty label); the detection-config handler treats this as the benign
		// fallback and shows the raw principal id rather than logging.
		{name: "missing user surfaces not-found", principalID: api.UserPrincipalID(999999), want: "", wantErr: api.ErrUserNotFound},
		// A missing service account surfaces the store's not-found from NameByID.
		{name: "missing service account surfaces not-found", principalID: api.ServiceAccountPrincipalID(999999), want: "", wantErr: serviceaccounts.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := svc.PrincipalLabel(t.Context(), tc.principalID)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
