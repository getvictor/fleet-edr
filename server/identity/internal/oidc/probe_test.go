package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fleetdm/edr/server/identity/internal/oidc"
	"github.com/stretchr/testify/require"
)

// discoveryServer serves a minimal OIDC discovery document. go-oidc requires the doc's `issuer` to equal the URL it was fetched from,
// so the handler reads the issuer var captured after the server starts. withToken toggles the token_endpoint to exercise the
// "advertises no token endpoint" branch.
func discoveryServer(t *testing.T, withToken bool) *httptest.Server {
	t.Helper()
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"jwks_uri":               issuer + "/keys",
		}
		if withToken {
			doc["token_endpoint"] = issuer + "/token"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	srv := httptest.NewServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func TestProbe_reachableIssuerVerifies(t *testing.T) {
	t.Parallel()
	srv := discoveryServer(t, true)
	require.NoError(t, oidc.Probe(t.Context(), srv.URL, srv.Client()))
}

func TestProbe_emptyIssuer(t *testing.T) {
	t.Parallel()
	require.Error(t, oidc.Probe(t.Context(), "", nil))
}

func TestProbe_unreachableIssuer(t *testing.T) {
	t.Parallel()
	// A server that is closed immediately: the discovery fetch fails to connect.
	srv := httptest.NewServer(http.NewServeMux())
	url := srv.URL
	client := srv.Client()
	srv.Close()
	require.Error(t, oidc.Probe(t.Context(), url, client))
}

func TestProbe_discoveryWithoutTokenEndpoint(t *testing.T) {
	t.Parallel()
	srv := discoveryServer(t, false)
	err := oidc.Probe(t.Context(), srv.URL, srv.Client())
	require.Error(t, err, "a discovery doc advertising no token endpoint must fail the probe")
}
