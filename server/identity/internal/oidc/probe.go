package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

// Probe verifies an issuer is reachable and advertises a token endpoint, without building a full client (no client id/secret/redirect
// required). It backs the admin test-connection action: a discovery-document fetch plus a token-endpoint presence check, run against a
// candidate issuer before the admin saves. Returns nil on success or a descriptive error on failure. It persists nothing.
func Probe(ctx context.Context, issuer string, httpClient *http.Client) error {
	if issuer == "" {
		return errors.New("oidc: issuer is required")
	}
	if httpClient != nil {
		ctx = gooidc.ClientContext(ctx, httpClient)
	}
	prov, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("oidc: discover %q: %w", issuer, err)
	}
	if prov.Endpoint().TokenURL == "" {
		return errors.New("oidc: discovery document advertises no token endpoint")
	}
	return nil
}
