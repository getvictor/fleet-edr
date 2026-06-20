package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
)

// ErrNotConfigured signals that no OIDC provider configuration exists yet: the deployment is break-glass-only until an admin
// configures SSO. The login/callback handlers map it to a directed "SSO not configured" response rather than a 500.
var ErrNotConfigured = errors.New("oidc: not configured")

// ProviderConfig is the connection-shaping subset the resolver needs to build a Client. Version is the stored config_version; the
// resolver rebuilds its cached Client whenever Version changes, so any edit (issuer, client id, secret, redirect, scopes) takes
// effect on the next login without a server restart.
type ProviderConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Version      int64
}

// ConfigFunc supplies the current provider configuration. It returns ErrNotConfigured when OIDC is unset for the deployment.
type ConfigFunc func(ctx context.Context) (ProviderConfig, error)

// Resolver builds and caches an *Client from the current stored configuration, rebuilding when config_version changes. It is the
// runtime-reconfiguration seam that replaces the boot-once client: the login path calls Current per request. Safe for concurrent use.
//
// The cached Client is a per-replica performance cache (ADR-0010, stateless server): it holds no state a peer replica needs and is
// safe to lose. Losing it only forces one OIDC discovery on the next login. Each replica notices a config change independently via the
// version bump on its next Current call, so no cross-replica signalling is required.
type Resolver struct {
	config ConfigFunc
	// build constructs an IDPClient from a config. Production wraps New (OIDC discovery); the seam lets the package's own tests exercise
	// the cache/rebuild logic without a live discovery endpoint.
	build clientBuilder

	mu            sync.Mutex
	cachedVersion int64
	cached        IDPClient
}

// clientBuilder constructs the per-config IDPClient. Returns an error on provider-build failure (e.g. discovery unreachable).
type clientBuilder func(ctx context.Context, cfg ProviderConfig) (IDPClient, error)

// NewResolver builds a Resolver. config is required; httpClient is optional (tests inject a fixture); logger defaults to slog.Default.
func NewResolver(config ConfigFunc, httpClient *http.Client, logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}
	return newResolverWithBuilder(config, func(ctx context.Context, cfg ProviderConfig) (IDPClient, error) {
		return New(ctx, Options{
			Issuer:       cfg.Issuer,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			HTTPClient:   httpClient,
			Logger:       logger,
		})
	})
}

// newResolverWithBuilder is the testable constructor: it takes the client builder directly so package tests can count builds and
// inject fakes without standing up an OIDC discovery server.
func newResolverWithBuilder(config ConfigFunc, build clientBuilder) *Resolver {
	if config == nil {
		panic("oidc.NewResolver: config func is required")
	}
	return &Resolver{config: config, build: build}
}

// Current returns the IDPClient for the current configuration, building and caching it on first use or after a config change. It
// propagates ErrNotConfigured from the config func unchanged so callers can distinguish "OIDC is off" from a build failure.
func (r *Resolver) Current(ctx context.Context) (IDPClient, error) {
	cfg, err := r.config(ctx)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	if r.cached != nil && r.cachedVersion == cfg.Version {
		c := r.cached
		r.mu.Unlock()
		return c, nil
	}
	r.mu.Unlock()

	// Build outside the lock: the builder runs OIDC discovery (a network round-trip), and holding the mutex across it would serialize
	// every concurrent login during a rebuild.
	client, err := r.build(ctx, cfg)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	// A concurrent caller may have already cached this version; either built client is correct, so only adopt ours when the cache is
	// empty or still on an older version.
	if r.cached == nil || r.cachedVersion != cfg.Version {
		r.cached = client
		r.cachedVersion = cfg.Version
	}
	c := r.cached
	r.mu.Unlock()
	return c, nil
}
