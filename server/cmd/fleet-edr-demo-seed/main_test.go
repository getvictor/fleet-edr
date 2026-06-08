package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
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
	s := newSeeder(config{demoOIDCSubject: ""}, nil, testHTTPClient(), discardLogger())
	require.NoError(t, s.seedUserIfConfigured(context.Background()))
}

func TestDBErrorsPropagate(t *testing.T) {
	s := newSeeder(config{pollInterval: time.Millisecond, verifyTimeout: 30 * time.Millisecond}, badDB(t), testHTTPClient(), discardLogger())
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

func TestNewHTTPClient(t *testing.T) {
	t.Run("no ca cert keeps default verification", func(t *testing.T) {
		c, err := newHTTPClient("")
		require.NoError(t, err)
		tr, ok := c.Transport.(*http.Transport)
		require.True(t, ok)
		// Clone() of DefaultTransport may carry a TLSClientConfig (h2 NextProtos etc.); what matters is that verification is
		// intact: no custom roots and not insecure.
		if tr.TLSClientConfig != nil {
			assert.Nil(t, tr.TLSClientConfig.RootCAs)
			assert.False(t, tr.TLSClientConfig.InsecureSkipVerify)
		}
	})

	t.Run("valid ca cert sets a RootCAs pool", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.pem")
		require.NoError(t, os.WriteFile(path, selfSignedCertPEM(t), 0o600))
		c, err := newHTTPClient(path)
		require.NoError(t, err)
		tr, ok := c.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, tr.TLSClientConfig)
		assert.NotNil(t, tr.TLSClientConfig.RootCAs)
	})

	t.Run("missing ca file errors", func(t *testing.T) {
		_, err := newHTTPClient(filepath.Join(t.TempDir(), "nope.pem"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read ca cert")
	})

	t.Run("invalid pem errors", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.pem")
		require.NoError(t, os.WriteFile(path, []byte("not a pem"), 0o600))
		_, err := newHTTPClient(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no PEM certificates")
	})
}

// selfSignedCertPEM mints a throwaway self-signed certificate so the CA-cert path of newHTTPClient can be exercised.
func selfSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
