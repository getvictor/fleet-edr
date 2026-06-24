package httpserver_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/httpserver"
)

// writeSelfSignedPEM writes a fresh self-signed ecdsa cert + key to temp files and returns their paths, so ConfigureTLS (which
// loads from disk via tls.LoadX509KeyPair) sees real material.
func writeSelfSignedPEM(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

// TestConfigureTLS_MinVersionIsTLS13 pins the unconditional TLS 1.3 floor. The EDR_TLS_ALLOW_TLS12 opt-in was removed; the only
// client is the project's own modern Go agent, so there is no path to negotiate TLS 1.2. A future regression that lowers the floor
// must fail this test.
//
// spec:server-configuration/the-server-configuration-surface-is-intentionally-minimal/tls-1-2-cannot-be-enabled
func TestConfigureTLS_MinVersionIsTLS13(t *testing.T) {
	t.Parallel()
	certFile, keyFile := writeSelfSignedPEM(t)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second}

	require.NoError(t, httpserver.ConfigureTLS(t.Context(), srv, httpserver.TLSOptions{CertFile: certFile, KeyFile: keyFile}))

	require.NotNil(t, srv.TLSConfig)
	assert.Equal(t, uint16(tls.VersionTLS13), srv.TLSConfig.MinVersion, "TLS floor must be 1.3 with no opt-out to 1.2")
}
