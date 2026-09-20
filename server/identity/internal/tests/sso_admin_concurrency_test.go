package tests

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fleetdm/edr/server/identity/bootstrap"
	"github.com/fleetdm/edr/server/identity/internal/appconfig"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
	"github.com/fleetdm/edr/server/testdb/full"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The SSO settings save replaced the whole configuration, so a page left open, or a script that read the settings earlier, silently
// overwrote everything saved since (issue #1046). These drive the real routes against a real MySQL, because what is being tested is
// two tables' version counters and a transaction, and nothing below the database can show that.

// ssoSettings is the read shape these tests care about. Declared here rather than reaching into the handler's unexported response
// type, so the tests read the wire the way a client does.
type ssoSettings struct {
	Configured  bool   `json:"configured"`
	Issuer      string `json:"issuer"`
	ClientID    string `json:"client_id"`
	ExternalURL string `json:"external_url"`
	Version     string `json:"version"`
}

func getSSOSettings(t *testing.T, mux *http.ServeMux, uid int64) ssoSettings {
	t.Helper()
	req := adminActorCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/settings/sso", nil), uid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got ssoSettings
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	return got
}

// ssoSaveRequest builds a PUT of a well-formed configuration, varying only what a test is about. An empty version omits the field,
// which is the unconditional overwrite a script asks for. Building and sending are separate so a concurrency test can prepare every
// request on the test's own goroutine, where an assertion is allowed to fail.
func ssoSaveRequest(t *testing.T, uid int64, issuer, clientID, externalURL, version string) *http.Request {
	t.Helper()
	body := map[string]any{
		"issuer": issuer, "client_id": clientID, "external_url": externalURL,
		"scopes": []string{"openid", "email"}, "jit_enabled": true, "default_role": "analyst",
	}
	if version != "" {
		body["version"] = version
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return adminActorCtx(
		httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/settings/sso", strings.NewReader(string(raw))), uid)
}

func saveSSOSettings(t *testing.T, mux *http.ServeMux, uid int64, issuer, clientID, externalURL, version string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, ssoSaveRequest(t, uid, issuer, clientID, externalURL, version))
	return w
}

// newUnconfiguredIdentity wires the identity context against a real test DB with NOTHING seeded, which is the state a first save
// races in. newIdentityWithDiscovery seeds a configuration, so it cannot show that.
func newUnconfiguredIdentity(t *testing.T) (*bootstrap.Identity, *sqlx.DB) {
	t.Helper()
	db := full.Open(t)
	id, err := bootstrap.New(t.Context(), bootstrap.Deps{
		DB:                db,
		Logger:            slog.Default(),
		SessionSigningKey: fixedKey(1),
		OIDCSecretKey:     fixedKey(21),
		SessionAbsolute:   time.Hour,
		CleanupInterval:   time.Hour,
	})
	require.NoError(t, err)
	require.NoError(t, id.ApplySchema(t.Context()))
	return id, db
}

// A save naming the configuration it was editing is refused once somebody else has saved, and changes nothing. Asserting the stored
// values afterwards is the half that matters: a 409 that had already written would be worse than no check at all.
//
// spec:sso-configuration/a-save-can-name-the-configuration-it-was-editing/a-save-naming-a-superseded-configuration-is-refused
func TestSSOAdmin_aSaveNamingASupersededConfigurationIsRefusedAndChangesNothing(t *testing.T) {
	t.Parallel()
	idp := oidcDiscoveryServer(t)
	id, db, _, _ := newIdentityWithDiscovery(t, idp)
	uid := seedUser(t, db, "admin@itest.local")
	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)

	before := getSSOSettings(t, mux, uid)
	require.NotEmpty(t, before.Version)

	// Somebody else saves, using the version they read.
	other := saveSSOSettings(t, mux, uid, idp.URL, "theirs", "https://theirs.example.com", before.Version)
	require.Equal(t, http.StatusOK, other.Code, other.Body.String())

	// The stale save names the version read before that, and is refused.
	stale := saveSSOSettings(t, mux, uid, idp.URL, "mine", "https://mine.example.com", before.Version)
	require.Equal(t, http.StatusConflict, stale.Code, stale.Body.String())
	assert.Contains(t, stale.Body.String(), "version_conflict")

	after := getSSOSettings(t, mux, uid)
	assert.Equal(t, "theirs", after.ClientID, "the refused save must not have landed")
	assert.Equal(t, "https://theirs.example.com", after.ExternalURL)
}

// The version covers BOTH stored parts, and each part alone is enough to supersede it.
//
// This has to be driven through the stores rather than through the endpoint. The SSO save writes both tables every time, so their
// counters move together and a check on either one would catch a concurrent save through this endpoint; a test that raced two saves
// would pass with half the check missing. The parts are separate documents with separate counters, though, and app_config is the
// deployment's general settings document by design, so whatever settings surface lands there next moves its counter alone. These
// cases write each part the way such a caller would, which is also how the seed path already writes them.
//
// spec:sso-configuration/a-save-can-name-the-configuration-it-was-editing/a-change-to-either-stored-part-supersedes-a-version
func TestSSOAdmin_aChangeToEitherStoredPartSupersedesAVersion(t *testing.T) {
	t.Parallel()
	cases := map[string]func(t *testing.T, ssoStore *ssoconfig.Store, appStore *appconfig.Store, issuer string){
		"the deployment settings moved on their own": func(t *testing.T, _ *ssoconfig.Store, appStore *appconfig.Store, _ string) {
			t.Helper()
			cur, version, err := appStore.Get(t.Context())
			require.NoError(t, err)
			cur.ExternalURL = "https://moved-elsewhere.example.com"
			require.NoError(t, appStore.Put(t.Context(), cur, version, ""))
		},
		"the OIDC configuration moved on its own": func(t *testing.T, ssoStore *ssoconfig.Store, _ *appconfig.Store, issuer string) {
			t.Helper()
			require.NoError(t, ssoStore.Upsert(t.Context(), ssoconfig.UpsertInput{
				Issuer: issuer, ClientID: "moved-elsewhere", Scopes: []string{"openid"}, JITEnabled: true, DefaultRole: "analyst",
			}))
		},
	}
	for name, moveOnePart := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			idp := oidcDiscoveryServer(t)
			id, db, ssoStore, appStore := newIdentityWithDiscovery(t, idp)
			uid := seedUser(t, db, "admin@itest.local")
			mux := http.NewServeMux()
			id.RegisterAuthedRoutes(mux)

			before := getSSOSettings(t, mux, uid)
			moveOnePart(t, ssoStore, appStore, idp.URL)
			after := getSSOSettings(t, mux, uid)
			require.NotEqual(t, before.Version, after.Version, "moving either part must move the version the endpoint reports")

			stale := saveSSOSettings(t, mux, uid, idp.URL, "mine", "https://mine.example.com", before.Version)
			assert.Equal(t, http.StatusConflict, stale.Code, stale.Body.String())
		})
	}
}

// Two operators configuring SSO for the first time at the same time have a defined winner, and the loser is told rather than
// silently replacing the winner. The first save is the case with no row to lock and no version to compare, so it is the one an
// optimistic check has to be written for deliberately.
//
// spec:sso-configuration/a-save-can-name-the-configuration-it-was-editing/two-first-saves-have-one-winner
func TestSSOAdmin_twoFirstSavesHaveOneWinner(t *testing.T) {
	t.Parallel()
	idp := oidcDiscoveryServer(t)
	id, db := newUnconfiguredIdentity(t)
	uid := seedUser(t, db, "admin@itest.local")
	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)

	before := getSSOSettings(t, mux, uid)
	require.False(t, before.Configured, "this has to start with nothing stored for it to be a first save")
	require.NotEmpty(t, before.Version, "an unconfigured deployment still reports a version, or a first save could only overwrite")

	// Every request is built before any of them runs: a racing goroutine must do nothing but the call, because a failed assertion
	// off the test's own goroutine is not a test failure, it is a panic in something else.
	const racers = 6
	reqs := make([]*http.Request, racers)
	for i := range racers {
		reqs[i] = ssoSaveRequest(t, uid, idp.URL, fmt.Sprintf("racer-%d", i), "https://racer.example.com", before.Version)
	}
	codes := make([]int, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, reqs[i])
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()

	won := 0
	for i, code := range codes {
		switch code {
		case http.StatusOK:
			won++
		case http.StatusConflict:
		default:
			t.Errorf("racer %d got %d, which is neither winning nor being told it lost", i, code)
		}
	}
	assert.Equal(t, 1, won, "exactly one first save may win")

	after := getSSOSettings(t, mux, uid)
	assert.True(t, after.Configured)
	assert.Contains(t, after.ClientID, "racer-", "and what is stored is one racer's configuration, whole")
}

// A save that names no version still overwrites, which is what automation that means to set the configuration outright asks for.
// The check is opt-in for exactly this reason: a script should not have to read the settings first to be allowed to write them.
//
// spec:sso-configuration/a-save-can-name-the-configuration-it-was-editing/a-save-naming-no-version-overwrites
func TestSSOAdmin_aSaveNamingNoVersionOverwrites(t *testing.T) {
	t.Parallel()
	idp := oidcDiscoveryServer(t)
	id, db, _, _ := newIdentityWithDiscovery(t, idp)
	uid := seedUser(t, db, "admin@itest.local")
	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)

	before := getSSOSettings(t, mux, uid)
	// Move the configuration on, so a version the script might have held is stale by any measure.
	moved := saveSSOSettings(t, mux, uid, idp.URL, "moved", "https://moved.example.com", before.Version)
	require.Equal(t, http.StatusOK, moved.Code, moved.Body.String())

	script := saveSSOSettings(t, mux, uid, idp.URL, "from-script", "https://script.example.com", "")
	require.Equal(t, http.StatusOK, script.Code, script.Body.String())

	after := getSSOSettings(t, mux, uid)
	assert.Equal(t, "from-script", after.ClientID)
	assert.Equal(t, "https://script.example.com", after.ExternalURL)
}

// The version a save reports back describes the values reported with it, so a client can keep saving without re-reading. A response
// that paired a fresh version with values read a moment apart would hand the client a version whose check passes while it holds
// something else's configuration, which is the lost update wearing a version number.
//
// spec:sso-configuration/a-save-can-name-the-configuration-it-was-editing/a-save-reports-a-version-that-matches-what-it-saved
func TestSSOAdmin_aSaveReportsAVersionItsOwnValuesMatch(t *testing.T) {
	t.Parallel()
	idp := oidcDiscoveryServer(t)
	id, db, _, _ := newIdentityWithDiscovery(t, idp)
	uid := seedUser(t, db, "admin@itest.local")
	mux := http.NewServeMux()
	id.RegisterAuthedRoutes(mux)

	before := getSSOSettings(t, mux, uid)
	saved := saveSSOSettings(t, mux, uid, idp.URL, "first", "https://first.example.com", before.Version)
	require.Equal(t, http.StatusOK, saved.Code, saved.Body.String())
	var savedBody ssoSettings
	require.NoError(t, json.Unmarshal(saved.Body.Bytes(), &savedBody))
	require.Equal(t, "first", savedBody.ClientID)

	// The version the save reported is usable straight away, with no read in between.
	next := saveSSOSettings(t, mux, uid, idp.URL, "second", "https://second.example.com", savedBody.Version)
	assert.Equal(t, http.StatusOK, next.Code, next.Body.String())

	after := getSSOSettings(t, mux, uid)
	assert.Equal(t, "second", after.ClientID)
}
