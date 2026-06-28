package serviceaccounts

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/satoken"
)

type fakeVerifier struct {
	claims satoken.Claims
	err    error
}

func (f fakeVerifier) Verify(string, time.Time) (satoken.Claims, error) { return f.claims, f.err }

type fakeAllow struct{ allowed bool }

func (f fakeAllow) Allowed(string, int64) bool { return f.allowed }

func TestAuthenticator_validTokenResolvesActor(t *testing.T) {
	t.Parallel()
	a := NewAuthenticator(
		fakeVerifier{claims: satoken.Claims{Subject: "sa_abc", Role: "analyst", Epoch: 3, Principal: "svc_7", Label: "ci-bot"}},
		fakeAllow{allowed: true},
	)
	actor, ok := a.Authenticate("token", time.Now())
	require.True(t, ok)
	require.NotNil(t, actor)
	assert.Equal(t, AuthMethodServiceAccount, actor.AuthMethod)
	assert.False(t, actor.SessionFresh, "a machine actor is never session-fresh; the chokepoint exempts it from the reauth gate by identity, not by faking freshness")
	assert.Equal(t, int64(0), actor.UserID, "a service account has no human user id")
	require.Len(t, actor.Roles, 1)
	assert.Equal(t, "analyst", actor.Roles[0].RoleID)
	assert.Equal(t, api.RoleBindingScopeGlobal, actor.Roles[0].ScopeType)
	// The acting service account survives authentication as a typed principal (the root fix for #514/#518): id + label come from the
	// token claims, with no DB read.
	assert.Equal(t, "svc_7", actor.Principal.ID)
	assert.Equal(t, api.PrincipalServiceAccount, actor.Principal.Type)
	assert.Equal(t, "ci-bot", actor.Principal.Label)
	_, isUser := actor.Principal.UserID()
	assert.False(t, isUser, "a service-account principal must never read as a user")
}

func TestAuthenticator_invalidTokenRejected(t *testing.T) {
	t.Parallel()
	a := NewAuthenticator(fakeVerifier{err: errors.New("bad")}, fakeAllow{allowed: true})
	actor, ok := a.Authenticate("token", time.Now())
	assert.False(t, ok)
	assert.Nil(t, actor)
}

func TestAuthenticator_revokedRejected(t *testing.T) {
	t.Parallel()
	// Token verifies but the revocation snapshot disallows it (revoked or stale epoch).
	a := NewAuthenticator(
		fakeVerifier{claims: satoken.Claims{Subject: "sa_abc", Role: "analyst", Epoch: 1}},
		fakeAllow{allowed: false},
	)
	actor, ok := a.Authenticate("token", time.Now())
	assert.False(t, ok)
	assert.Nil(t, actor)
}
