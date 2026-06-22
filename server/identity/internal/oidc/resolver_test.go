package oidc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubClient is a minimal IDPClient the resolver can cache and hand back; identity is compared by pointer in the tests.
type stubClient struct{ id string }

func (s *stubClient) AuthURL(_, _, _ string) string { return s.id }
func (s *stubClient) Exchange(context.Context, string, string, string) (*Claims, error) {
	return &Claims{Subject: s.id}, nil
}

// spec:server-identity-authentication/okta-oidc-is-the-primary-login-path/a-configuration-change-applies-to-the-next-login-without-restart
// spec:sso-configuration/configuration-changes-apply-without-a-server-restart/a-saved-change-takes-effect-on-the-next-login
func TestResolver_cachesUntilVersionChanges(t *testing.T) {
	t.Parallel()
	var cfg atomic.Pointer[ProviderConfig]
	cfg.Store(&ProviderConfig{Issuer: "https://a.example.com", Stamp: "1"})

	var builds atomic.Int64
	r := newResolverWithBuilder(
		func(context.Context) (ProviderConfig, error) { return *cfg.Load(), nil },
		func(_ context.Context, c ProviderConfig) (IDPClient, error) {
			builds.Add(1)
			return &stubClient{id: c.Issuer}, nil
		},
	)

	// First call builds; repeated calls at the same version reuse the cached client (one build total).
	first, err := r.Current(t.Context())
	require.NoError(t, err)
	for range 5 {
		again, err := r.Current(t.Context())
		require.NoError(t, err)
		assert.Same(t, first, again, "same version must return the cached client")
	}
	assert.Equal(t, int64(1), builds.Load(), "no rebuild while version is unchanged")

	// A config change (new issuer + bumped version) forces exactly one rebuild, reflecting the new issuer without a restart.
	cfg.Store(&ProviderConfig{Issuer: "https://b.example.com", Stamp: "2"})
	rebuilt, err := r.Current(t.Context())
	require.NoError(t, err)
	assert.NotSame(t, first, rebuilt, "a version bump must rebuild")
	assert.Equal(t, "https://b.example.com", rebuilt.AuthURL("", "", ""))
	assert.Equal(t, int64(2), builds.Load())
}

func TestResolver_propagatesNotConfigured(t *testing.T) {
	t.Parallel()
	r := newResolverWithBuilder(
		func(context.Context) (ProviderConfig, error) { return ProviderConfig{}, ErrNotConfigured },
		func(context.Context, ProviderConfig) (IDPClient, error) {
			t.Fatal("builder must not run when config is unset")
			return nil, nil
		},
	)
	_, err := r.Current(t.Context())
	require.ErrorIs(t, err, ErrNotConfigured)
}

func TestResolver_propagatesBuildError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("discovery unreachable")
	r := newResolverWithBuilder(
		func(context.Context) (ProviderConfig, error) {
			return ProviderConfig{Issuer: "https://x", Stamp: "1"}, nil
		},
		func(context.Context, ProviderConfig) (IDPClient, error) { return nil, wantErr },
	)
	_, err := r.Current(t.Context())
	require.ErrorIs(t, err, wantErr)
}

func TestResolver_concurrentCurrentIsSafe(t *testing.T) {
	t.Parallel()
	r := newResolverWithBuilder(
		func(context.Context) (ProviderConfig, error) {
			return ProviderConfig{Issuer: "https://a", Stamp: "1"}, nil
		},
		func(_ context.Context, c ProviderConfig) (IDPClient, error) { return &stubClient{id: c.Issuer}, nil },
	)
	const n = 20
	clients := make([]IDPClient, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			clients[i], errs[i] = r.Current(t.Context())
		})
	}
	wg.Wait()
	for i := range n {
		require.NoError(t, errs[i])
		require.NotNil(t, clients[i])
	}
}
