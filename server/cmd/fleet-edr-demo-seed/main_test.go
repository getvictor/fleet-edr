package main

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// badDB returns a handle whose connections always fail fast, to exercise DB error branches without a live server.
func badDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("mysql", "root:nope@tcp(127.0.0.1:1)/x?timeout=300ms")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRealMainMissingDSN(t *testing.T) {
	err := realMain(discardLogger(), func(string) string { return "" }, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DSN is required")
}

func TestRealMainPingFails(t *testing.T) {
	getenv := func(k string) string {
		if k == "EDR_DSN" {
			return "root:nope@tcp(127.0.0.1:1)/x?timeout=300ms"
		}
		return ""
	}
	err := realMain(discardLogger(), getenv, []string{"--ready-timeout=200ms", "--verify-timeout=200ms"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ping mysql")
}

func TestSeedUserIfConfiguredNoSubject(t *testing.T) {
	s := newSeeder(config{demoOIDCSubject: ""}, nil, discardLogger())
	require.NoError(t, s.seedUserIfConfigured(context.Background()))
}

func TestDBErrorsPropagate(t *testing.T) {
	s := newSeeder(config{pollInterval: time.Millisecond, verifyTimeout: 30 * time.Millisecond}, badDB(t), discardLogger())
	ctx := context.Background()

	_, err := s.counts(ctx)
	require.Error(t, err)

	_, err = s.alreadySeeded(ctx)
	require.Error(t, err)

	err = s.verify(ctx)
	require.Error(t, err)

	err = s.waitForProcess(ctx, "HOST", 1)
	require.Error(t, err)
}

func TestSeedDemoUserError(t *testing.T) {
	err := seedDemoUser(context.Background(), badDB(t), "demo@fleet-edr.local", "subject", "senior_analyst")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "seed demo user row")
}

func TestNewHTTPClientInsecure(t *testing.T) {
	tr, ok := newHTTPClient(true).Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, tr.TLSClientConfig)
	assert.True(t, tr.TLSClientConfig.InsecureSkipVerify)

	tr, ok = newHTTPClient(false).Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.TLSClientConfig)
}
