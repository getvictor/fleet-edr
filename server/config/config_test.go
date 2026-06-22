package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validTestSecretKey is a >=32-byte EDR_SECRET_KEY that envMap injects by default so the many positive cases don't each have to set
// it. A case exercising the missing/short-key validation sets EDR_SECRET_KEY explicitly: an empty string opts out of the default and
// drives the "required" error, a short string drives the length error.
const validTestSecretKey = "test-secret-key-0123456789abcdef0123456789"

func envMap(pairs map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := pairs[k]; ok {
			return v
		}
		// EDR_SECRET_KEY is required by every boot; default it so cases that don't care about it still load. Presence in the map
		// (even as "") opts out, which is how the missing/short-key negative cases are written.
		if k == "EDR_SECRET_KEY" {
			return validTestSecretKey
		}
		return ""
	}
}

// writeTestCert generates a fresh self-signed ed25519 cert + key pair in tb.TempDir() and returns the file paths. Tests pass the
// paths to EDR_TLS_CERT_FILE / EDR_TLS_KEY_FILE so loadTLSConfig's tls.LoadX509KeyPair fail-fast check (CodeRabbit PR #182)
// sees real material; ed25519 is small, generates instantly, and avoids the RSA keygen cost across the many config tests.
func writeTestCert(tb testing.TB) (certFile, keyFile string) {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(tb, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(tb, err)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(tb, err)

	dir := tb.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	require.NoError(tb, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(tb, os.WriteFile(keyFile, keyPEM, 0o600))
	return certFile, keyFile
}

func TestLoad(t *testing.T) {
	// Minimal env: every dev + prod deployment must supply TLS cert + key (issue #140 removed the EDR_ALLOW_INSECURE_HTTP opt-out).
	// EDR_AUTH_ALLOW_NO_OIDC stays as the deliberate break-glass-only dev opt-out; the OIDC-required interaction is covered in
	// TestLoad_OIDCConfig below.
	certFile, keyFile := writeTestCert(t)
	minEnv := map[string]string{
		"EDR_DSN":                "root@tcp(127.0.0.1:3306)/edr?parseTime=true",
		"EDR_ENROLL_SECRET":      "enroll-me",
		"EDR_TLS_CERT_FILE":      certFile,
		"EDR_TLS_KEY_FILE":       keyFile,
		"EDR_AUTH_ALLOW_NO_OIDC": "1",
	}

	cases := []struct {
		name     string
		env      map[string]string
		wantErr  string
		validate func(t *testing.T, c *Config)
	}{
		{
			name: "happy path with required vars only",
			env:  minEnv,
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "root@tcp(127.0.0.1:3306)/edr?parseTime=true", c.DSN)
				assert.Equal(t, "enroll-me", c.EnrollSecret)
				assert.True(t, c.TLSEnabled(), "TLS must always be enabled: no plaintext-HTTP mode (issue #140)")
				assert.Equal(t, ":8088", c.ListenAddr)
				assert.Equal(t, "info", c.LogLevel)
				assert.Equal(t, "json", c.LogFormat)
				assert.Equal(t, 30, c.EnrollRatePerMin)
			},
		},
		{
			// Removed tuning knobs must be inert: setting them (even to unparseable junk that the old parsers would have
			// rejected) must not fail boot. The trimmed surface ignores them and uses the fixed defaults.
			// spec:server-configuration/the-server-configuration-surface-is-intentionally-minimal/a-removed-tuning-variable-is-ignored-at-boot
			name: "removed tuning variables are inert",
			env: withExtra(minEnv, map[string]string{
				"EDR_PROCESS_INTERVAL":      "garbage",
				"EDR_HOST_TOKEN_LIFETIME":   "nonsense",
				"EDR_AUDIT_READ_SAMPLING":   "banana",
				"EDR_TLS_ALLOW_TLS12":       "1",
				"EDR_OIDC_STATE_COOKIE_TTL": "later",
				"EDR_MYSQL_ADDRESS":         "should-be-ignored",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "root@tcp(127.0.0.1:3306)/edr?parseTime=true", c.DSN, "EDR_DSN still wins; EDR_MYSQL_* is gone")
				assert.Equal(t, 30, c.EnrollRatePerMin, "kept default unaffected by inert vars")
			},
		},
		{
			// spec:server-configuration/the-server-configuration-surface-is-intentionally-minimal/the-database-requires-a-single-dsn
			name: "missing EDR_DSN",
			env: map[string]string{
				"EDR_ENROLL_SECRET": "s",
				"EDR_TLS_CERT_FILE": certFile,
				"EDR_TLS_KEY_FILE":  keyFile,
			},
			wantErr: "EDR_DSN",
		},
		{
			name: "missing EDR_ENROLL_SECRET",
			env: map[string]string{
				"EDR_DSN":           "x",
				"EDR_TLS_CERT_FILE": certFile,
				"EDR_TLS_KEY_FILE":  keyFile,
			},
			wantErr: "EDR_ENROLL_SECRET",
		},
		{
			// spec:server-identity-authentication/pre-auth-cookie-signing-keys-derive-from-the-deployment-root-secret/server-requires-the-root-secret-at-boot
			name: "missing EDR_SECRET_KEY",
			env: map[string]string{
				"EDR_DSN":           "x",
				"EDR_ENROLL_SECRET": "s",
				"EDR_TLS_CERT_FILE": certFile,
				"EDR_TLS_KEY_FILE":  keyFile,
				"EDR_SECRET_KEY":    "", // present-but-empty opts out of envMap's default, exercising the required check
			},
			wantErr: "EDR_SECRET_KEY is required",
		},
		{
			name: "short EDR_SECRET_KEY",
			env: map[string]string{
				"EDR_DSN":           "x",
				"EDR_ENROLL_SECRET": "s",
				"EDR_TLS_CERT_FILE": certFile,
				"EDR_TLS_KEY_FILE":  keyFile,
				"EDR_SECRET_KEY":    "tooshort",
			},
			wantErr: "EDR_SECRET_KEY must be at least 32 bytes",
		},
		{
			// spec:server-availability/tls-may-be-terminated-by-a-front-proxy/mandatory-tls-remains-the-default
			name: "TLS cert + key unconditionally required (no opt-out)",
			env: map[string]string{
				"EDR_DSN":           "x",
				"EDR_ENROLL_SECRET": "s",
			},
			wantErr: "EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE are both required",
		},
		{
			name: "TLS key without cert",
			env: map[string]string{
				"EDR_DSN":           "x",
				"EDR_ENROLL_SECRET": "s",
				"EDR_TLS_KEY_FILE":  "/tmp/edr.key",
			},
			wantErr: "EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE are both required",
		},
		{
			name: "TLS cert without key",
			env: map[string]string{
				"EDR_DSN":           "x",
				"EDR_ENROLL_SECRET": "s",
				"EDR_TLS_CERT_FILE": "/tmp/edr.crt",
			},
			wantErr: "EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE are both required",
		},
		{
			// spec:server-availability/tls-may-be-terminated-by-a-front-proxy/proxy-termination-opt-in-allows-plaintext-http
			name: "EDR_TLS_TERMINATED_BY_PROXY allows boot without certs",
			env: map[string]string{
				"EDR_DSN":                     "x",
				"EDR_ENROLL_SECRET":           "s",
				"EDR_AUTH_ALLOW_NO_OIDC":      "1",
				"EDR_TLS_TERMINATED_BY_PROXY": "1",
			},
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.True(t, c.TLSTerminatedByProxy)
				assert.False(t, c.TLSEnabled(), "proxy-terminated mode does not terminate TLS at the server")
			},
		},
		{
			// spec:server-availability/tls-may-be-terminated-by-a-front-proxy/proxy-flag-and-cert-files-are-mutually-exclusive
			name: "EDR_TLS_TERMINATED_BY_PROXY with cert files is rejected",
			env: map[string]string{
				"EDR_DSN":                     "x",
				"EDR_ENROLL_SECRET":           "s",
				"EDR_TLS_TERMINATED_BY_PROXY": "1",
				"EDR_TLS_CERT_FILE":           certFile,
				"EDR_TLS_KEY_FILE":            keyFile,
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "ExternalTLS true under proxy termination",
			env: map[string]string{
				"EDR_DSN":                     "x",
				"EDR_ENROLL_SECRET":           "s",
				"EDR_AUTH_ALLOW_NO_OIDC":      "1",
				"EDR_TLS_TERMINATED_BY_PROXY": "1",
			},
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.False(t, c.TLSEnabled(), "server does not terminate TLS in proxy mode")
				assert.True(t, c.ExternalTLS(), "external connection is HTTPS via the proxy, so cookies/HSTS stay secure")
			},
		},
		{
			name: "missing every required var reports each",
			env:  map[string]string{},
			validate: func(t *testing.T, _ *Config) {
				t.Helper()
				t.Fatalf("validate should not be called when wantErr is set")
			},
			wantErr: "EDR_DSN\nrequired env var EDR_ENROLL_SECRET",
		},
		{
			name: "bad log level",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_LEVEL": "spam",
			}),
			wantErr: `EDR_LOG_LEVEL="spam" must be one of debug, info, warn, error`,
		},
		{
			name: "bad log format",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_FORMAT": "xml",
			}),
			wantErr: `EDR_LOG_FORMAT="xml" must be 'json' or 'text'`,
		},
		{
			name: "log level normalized to lowercase",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_LEVEL": "WARN",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "warn", c.LogLevel)
			},
		},
		{
			name: "log format normalized to lowercase",
			env: withExtra(minEnv, map[string]string{
				"EDR_LOG_FORMAT": "JSON",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "json", c.LogFormat)
			},
		},
		{
			name: "optional overrides applied",
			env: withExtra(minEnv, map[string]string{
				"EDR_LISTEN_ADDR": "127.0.0.1:9090",
				"EDR_LOG_LEVEL":   "debug",
				"EDR_LOG_FORMAT":  "text",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "127.0.0.1:9090", c.ListenAddr)
				assert.Equal(t, "enroll-me", c.EnrollSecret)
				assert.Equal(t, "debug", c.LogLevel)
				assert.Equal(t, "text", c.LogFormat)
			},
		},
		{
			name: "EDR_TRUSTED_PROXIES populates and trims",
			env: withExtra(minEnv, map[string]string{
				// Mixed CIDR forms + whitespace + an empty entry. CIDR validation is deferred to
				// httpserver.NewClientIPResolver, so config-level parsing only trims and drops empties.
				"EDR_TRUSTED_PROXIES": " 10.0.0.0/8 , 192.168.1.5,, fd00::/8",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t,
					[]string{"10.0.0.0/8", "192.168.1.5", "fd00::/8"},
					c.TrustedProxies,
					"split must trim entries and drop the empty token")
			},
		},
		{
			name: "EDR_TRUSTED_PROXIES unset leaves nil slice",
			env:  minEnv,
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Nil(t, c.TrustedProxies,
					"unset env keeps the secure default: XFF ignored, peer IP used")
			},
		},
		{
			name: "EDR_TRUSTED_PROXIES with only whitespace yields nil",
			env: withExtra(minEnv, map[string]string{
				"EDR_TRUSTED_PROXIES": " , , ",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Nil(t, c.TrustedProxies,
					"all-empty input must collapse to nil rather than an empty slice")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadFrom(envMap(tc.env))
			if tc.wantErr != "" {
				require.Error(t, err)
				for fragment := range strings.SplitSeq(tc.wantErr, "\n") {
					assert.Contains(t, err.Error(), fragment)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			if tc.validate != nil {
				tc.validate(t, got)
			}
		})
	}
}

// TestLoad_OIDCConfig covers the Phase-4a auth-mode enforcement: a production deployment without OIDC config refuses to start;
// dev mode opts out via EDR_AUTH_ALLOW_NO_OIDC=1; setting OIDC_ISSUER without the rest produces focused per-field errors.
func TestLoad_OIDCConfig(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	prodLikeEnv := map[string]string{
		"EDR_DSN":           "root@tcp(127.0.0.1:3306)/edr?parseTime=true",
		"EDR_ENROLL_SECRET": "enroll-me",
		"EDR_TLS_CERT_FILE": certFile,
		"EDR_TLS_KEY_FILE":  keyFile,
	}

	cases := []struct {
		name     string
		env      map[string]string
		wantErr  string
		validate func(t *testing.T, c *Config)
	}{
		{
			name:    "no OIDC + no dev flag -> refuse",
			env:     prodLikeEnv,
			wantErr: "EDR_OIDC_ISSUER is required",
		},
		{
			name: "no OIDC + dev flag -> ok",
			env:  withExtra(prodLikeEnv, map[string]string{"EDR_AUTH_ALLOW_NO_OIDC": "1"}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.True(t, c.AuthAllowNoOIDC)
				assert.Empty(t, c.OIDCIssuer)
			},
		},
		{
			name: "issuer set without client_id -> per-field error",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER": "https://example.okta.com",
			}),
			wantErr: "EDR_OIDC_CLIENT_ID is required",
		},
		{
			name: "issuer + client_id without secret -> per-field error",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":    "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID": "edr",
			}),
			wantErr: "EDR_OIDC_CLIENT_SECRET is required",
		},
		{
			name: "issuer + client_id + secret without redirect -> per-field error",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":        "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":     "edr",
				"EDR_OIDC_CLIENT_SECRET": "shh",
			}),
			wantErr: "EDR_OIDC_REDIRECT_URL is required",
		},
		{
			name: "complete OIDC config -> ok with default scopes",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":        "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":     "edr",
				"EDR_OIDC_CLIENT_SECRET": "shh",
				"EDR_OIDC_REDIRECT_URL":  "https://edr.example.com/api/auth/callback",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "https://example.okta.com", c.OIDCIssuer)
				assert.Equal(t, "edr", c.OIDCClientID)
				assert.Equal(t, "shh", c.OIDCClientSecret)
				assert.Equal(t, "https://edr.example.com/api/auth/callback", c.OIDCRedirectURL)
				assert.True(t, c.OIDCAllowJITProvisioning)
				assert.Empty(t, c.OIDCDefaultRole, "default JIT role falls through to the identity-context default")
				assert.False(t, c.AuthAllowNoOIDC)
			},
		},
		{
			name: "EDR_OIDC_ALLOW_JIT_PROVISIONING=0 disables JIT",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":                 "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":              "edr",
				"EDR_OIDC_CLIENT_SECRET":          "shh",
				"EDR_OIDC_REDIRECT_URL":           "https://edr.example.com/api/auth/callback",
				"EDR_OIDC_ALLOW_JIT_PROVISIONING": "0",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.False(t, c.OIDCAllowJITProvisioning)
			},
		},
		{
			name: "EDR_OIDC_DEFAULT_ROLE override",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":        "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":     "edr",
				"EDR_OIDC_CLIENT_SECRET": "shh",
				"EDR_OIDC_REDIRECT_URL":  "https://edr.example.com/api/auth/callback",
				"EDR_OIDC_DEFAULT_ROLE":  "admin",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "admin", c.OIDCDefaultRole)
			},
		},
		{
			name: "EDR_OIDC_DEFAULT_ROLE is normalized (trim + lowercase)",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":        "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":     "edr",
				"EDR_OIDC_CLIENT_SECRET": "shh",
				"EDR_OIDC_REDIRECT_URL":  "https://edr.example.com/api/auth/callback",
				"EDR_OIDC_DEFAULT_ROLE":  "  Senior_Analyst  ",
			}),
			validate: func(t *testing.T, c *Config) {
				t.Helper()
				assert.Equal(t, "senior_analyst", c.OIDCDefaultRole)
			},
		},
		{
			name: "EDR_OIDC_DEFAULT_ROLE unknown role -> error listing allowed values",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_ISSUER":        "https://example.okta.com",
				"EDR_OIDC_CLIENT_ID":     "edr",
				"EDR_OIDC_CLIENT_SECRET": "shh",
				"EDR_OIDC_REDIRECT_URL":  "https://edr.example.com/api/auth/callback",
				"EDR_OIDC_DEFAULT_ROLE":  "wizard",
			}),
			wantErr: "EDR_OIDC_DEFAULT_ROLE \"wizard\" is not a known role",
		},
		{
			name: "EDR_OIDC_DEFAULT_ROLE without issuer -> partial-OIDC error",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_OIDC_DEFAULT_ROLE":  "admin",
				"EDR_AUTH_ALLOW_NO_OIDC": "1",
			}),
			wantErr: "set without EDR_OIDC_ISSUER",
		},
		{
			// Partial OIDC config + EDR_AUTH_ALLOW_NO_OIDC=1 must NOT silently disable OIDC. A typo in EDR_OIDC_ISSUER
			// while EDR_OIDC_CLIENT_ID is set is unmistakeably an OIDC intent; falling through to break-glass-only mode
			// masks the misconfiguration.
			name: "partial OIDC config + allow-no-oidc still refuses",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_AUTH_ALLOW_NO_OIDC": "1",
				"EDR_OIDC_CLIENT_ID":     "edr",
			}),
			wantErr: "set without EDR_OIDC_ISSUER",
		},
		{
			// Same as above but with the secret set instead of client_id.
			name: "partial OIDC (secret only) + allow-no-oidc still refuses",
			env: withExtra(prodLikeEnv, map[string]string{
				"EDR_AUTH_ALLOW_NO_OIDC": "1",
				"EDR_OIDC_CLIENT_SECRET": "shh",
			}),
			wantErr: "set without EDR_OIDC_ISSUER",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadFrom(envMap(tc.env))
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			if tc.validate != nil {
				tc.validate(t, got)
			}
		})
	}
}

func withExtra(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	maps.Copy(out, base)
	maps.Copy(out, extra)
	return out
}

// TestDefaultOIDCScopes pins the fixed OIDC scope set wired at boot (EDR_OIDC_SCOPES was removed) and confirms each call returns a
// fresh slice so a caller can't mutate a shared backing array.
func TestDefaultOIDCScopes(t *testing.T) {
	assert.Equal(t, []string{"openid", "email", "profile"}, DefaultOIDCScopes())
	a := DefaultOIDCScopes()
	a[0] = "mutated"
	assert.Equal(t, []string{"openid", "email", "profile"}, DefaultOIDCScopes(), "must return a fresh slice each call")
}

// TestLoad_TLSCertFailFast pins the fail-fast behaviour added in response to a CodeRabbit review on PR #182: bad cert paths
// must surface during config.Load, before any caller mutates DB state (schema apply, admin seeding). Without this, a typoed
// EDR_TLS_CERT_FILE used to escape Config validation and only failed inside configureTLS, long after the first-boot admin
// password had been printed to the log.
func TestLoad_TLSCertFailFast(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	base := map[string]string{
		"EDR_DSN":                "root@tcp(127.0.0.1:3306)/edr?parseTime=true",
		"EDR_ENROLL_SECRET":      "enroll-me",
		"EDR_AUTH_ALLOW_NO_OIDC": "1",
	}

	t.Run("nonexistent cert file rejected at Load time", func(t *testing.T) {
		env := withExtra(base, map[string]string{
			"EDR_TLS_CERT_FILE": filepath.Join(t.TempDir(), "does-not-exist.crt"),
			"EDR_TLS_KEY_FILE":  keyFile,
		})
		_, err := loadFrom(envMap(env))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EDR_TLS_CERT_FILE/EDR_TLS_KEY_FILE unreadable or mismatched")
	})

	t.Run("mismatched cert + key rejected at Load time", func(t *testing.T) {
		// Swap in a fresh key that doesn't match the cert.
		_, mismatchKey := writeTestCert(t)
		env := withExtra(base, map[string]string{
			"EDR_TLS_CERT_FILE": certFile,
			"EDR_TLS_KEY_FILE":  mismatchKey,
		})
		_, err := loadFrom(envMap(env))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EDR_TLS_CERT_FILE/EDR_TLS_KEY_FILE unreadable or mismatched")
	})

	t.Run("valid cert + key passes", func(t *testing.T) {
		env := withExtra(base, map[string]string{
			"EDR_TLS_CERT_FILE": certFile,
			"EDR_TLS_KEY_FILE":  keyFile,
		})
		cfg, err := loadFrom(envMap(env))
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.True(t, cfg.TLSEnabled())
	})
}
