package config

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// request is a request to the given URL, which is all ProxyFunc reads.
func request(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &http.Request{URL: u}
}

// proxyFor returns the proxy chosen for rawURL, as a string, or "" for a direct connection.
func proxyFor(t *testing.T, p ProxyConfig, rawURL string) string {
	t.Helper()
	chosen, err := p.ProxyFunc()(request(t, rawURL))
	require.NoError(t, err)
	if chosen == nil {
		return ""
	}
	return chosen.String()
}

// The bug this closes: the conf file is where the launchd plist tells operators all tunables live, and a proxy set there reached
// nothing, because the agent read http.ProxyFromEnvironment and that is the process environment.
//
// Driven through loadFromEnv with an empty process environment and the setting only in the conf map, which is exactly the shape
// that silently did nothing.
//
// spec:agent-configuration/the-agent-configuration-surface-is-intentionally-minimal/a-proxy-set-in-the-conf-file-is-used
func TestAProxyFromTheConfFileIsUsed(t *testing.T) {
	t.Parallel()
	cfg, err := loadFrom(layeredGetenv(
		map[string]string{ //nolint:gosec // G101: the credential in this URL is the input under test: it must never leave the agent.
			"EDR_SERVER_URL": "https://edr.example.com:8443",
			"HTTPS_PROXY":    "socks5://proxy.corp:1080",
		},
		func(string) (string, bool) { return "", false }, // nothing in the process environment
	))
	require.NoError(t, err)

	assert.Equal(t, "socks5://proxy.corp:1080", cfg.Proxy.HTTPSProxy)
	assert.True(t, cfg.Proxy.Set())
	assert.Equal(t, "socks5://proxy.corp:1080", proxyFor(t, cfg.Proxy, "https://edr.example.com:8443"))
}

// The process environment still wins, so an operator can override one host without editing the file. That is the layering every
// other setting already has, and a proxy that ignored it would be a new surprise in place of the old one.
func TestTheProcessEnvironmentOverridesTheConfFile(t *testing.T) {
	t.Parallel()
	cfg, err := loadFrom(layeredGetenv(
		map[string]string{ //nolint:gosec // G101: the credential in this URL is the input under test: it must never leave the agent.
			"EDR_SERVER_URL": "https://edr.example.com:8443",
			"HTTPS_PROXY":    "http://from-the-conf-file:3128",
		},
		func(name string) (string, bool) {
			if name == "HTTPS_PROXY" {
				return "http://from-the-environment:3128", true
			}
			return "", false
		},
	))
	require.NoError(t, err)

	assert.Equal(t, "http://from-the-environment:3128", proxyFor(t, cfg.Proxy, "https://edr.example.com:8443"))
}

// Whichever case the operator wrote. net/http reads both, so an agent that read only one would work for some hosts and not
// others depending on how the variable had been spelled.
func TestEitherCaseOfTheVariableIsRead(t *testing.T) {
	t.Parallel()
	lower := loadProxy(func(name string) string {
		switch name {
		case "https_proxy":
			return "http://lower:3128"
		case "http_proxy":
			return "http://lower-http:3128"
		case "no_proxy":
			return "internal.example.com"
		}
		return ""
	})
	assert.Equal(t, "http://lower:3128", lower.HTTPSProxy)
	assert.Equal(t, "http://lower-http:3128", lower.HTTPProxy)
	assert.Equal(t, "internal.example.com", lower.NoProxy)

	// Uppercase wins when both are set, which is the order net/http itself uses.
	both := loadProxy(func(name string) string {
		switch name {
		case "HTTPS_PROXY":
			return "http://upper:3128"
		case "https_proxy":
			return "http://lower:3128"
		}
		return ""
	})
	assert.Equal(t, "http://upper:3128", both.HTTPSProxy)
}

// The scheme and NO_PROXY rules are httpproxy's, the package net/http builds ProxyFromEnvironment on, so an operator's existing
// expectations carry over rather than meeting a second interpretation of the same variables.
func TestTheSchemeAndNoProxyRulesAreTheOnesOperatorsExpect(t *testing.T) {
	t.Parallel()
	p := ProxyConfig{
		HTTPProxy:  "http://plain:3128",
		HTTPSProxy: "http://secure:3128",
		NoProxy:    "internal.example.com,10.0.0.0/8",
	}

	assert.Equal(t, "http://secure:3128", proxyFor(t, p, "https://edr.example.com:8443"), "an https server URL takes HTTPS_PROXY")
	assert.Equal(t, "http://plain:3128", proxyFor(t, p, "http://edr.example.com:8080"), "an http one takes HTTP_PROXY")
	assert.Empty(t, proxyFor(t, p, "https://internal.example.com:8443"), "a NO_PROXY host is reached directly")
	assert.Empty(t, proxyFor(t, p, "https://10.1.2.3:8443"), "and so is one inside a NO_PROXY range")
}

// No proxy configured must mean a direct connection, not an error and not an empty proxy URL that a dial would then try to use.
func TestNoProxyConfiguredMeansDirect(t *testing.T) {
	t.Parallel()
	var p ProxyConfig

	assert.False(t, p.Set())
	assert.Empty(t, proxyFor(t, p, "https://edr.example.com:8443"))
}

// The leak this closes. An operator who writes a scheme the agent cannot speak still had its HTTP transport connect to that host
// and send the credentials from the address, as Basic, in the clear: net/http picks its proxy behaviour from the TARGET's scheme
// rather than the proxy's, and the resolver underneath validates no scheme at all. Measured on edr-dev (issue #1128).
//
// Driven through the layered load, which is how a conf-file setting actually reaches the agent.
//
// spec:agent-configuration/a-proxy-the-agent-cannot-speak-is-refused-rather-than-used/a-refused-proxy-receives-nothing
func TestAProxySchemeTheAgentCannotSpeakIsRefused(t *testing.T) {
	t.Parallel()
	cfg, err := loadFrom(layeredGetenv(
		map[string]string{ //nolint:gosec // G101: the credential in this URL is the input under test: it must never leave the agent.
			"EDR_SERVER_URL": "https://edr.example.com:8443",
			"HTTPS_PROXY":    "ftp://ir:s3cret@proxy.corp:2121",
		},
		func(string) (string, bool) { return "", false },
	))
	require.NoError(t, err)

	assert.Empty(t, cfg.Proxy.HTTPSProxy, "a setting the agent cannot use must not be carried as if it could")
	assert.False(t, cfg.Proxy.Set(), "and Set must not claim a proxy is configured")
	assert.Empty(t, proxyFor(t, cfg.Proxy, "https://edr.example.com:8443"), "so every path connects directly")
}

// What the operator is told. The setting's name is what they search their conf file for, and the scheme is what they got wrong.
// The VALUE is deliberately absent: it carries the credentials this change exists to keep off the wire, and a log is a wire.
//
// spec:agent-configuration/a-proxy-the-agent-cannot-speak-is-refused-rather-than-used/the-operator-is-told-which-setting-was-refused
func TestARefusedProxyIsReportedByNameAndScheme(t *testing.T) {
	t.Parallel()
	cfg, err := loadFrom(layeredGetenv(
		map[string]string{ //nolint:gosec // G101: the credential in this URL is the input under test: it must never leave the agent.
			"EDR_SERVER_URL": "https://edr.example.com:8443",
			"HTTPS_PROXY":    "ftp://ir:s3cret@proxy.corp:2121",
			"HTTP_PROXY":     "gopher://proxy.corp:70",
		},
		func(string) (string, bool) { return "", false },
	))
	require.NoError(t, err)

	assert.Equal(t, []RefusedProxy{
		{Setting: "HTTP_PROXY", Scheme: "gopher"},
		{Setting: "HTTPS_PROXY", Scheme: "ftp"},
	}, cfg.Proxy.Refused)
	for _, refused := range cfg.Proxy.Refused {
		assert.NotContains(t, refused.Setting+refused.Scheme, "s3cret", "the credential must not ride the report")
	}
}

// The invariant, rather than the convention. The loader is one way a ProxyConfig comes into being, and a caller that builds one
// directly would otherwise hand a dialer a proxy the agent cannot speak.
func TestProxyFuncRefusesAnUnspeakableSchemeHoweverTheConfigWasBuilt(t *testing.T) {
	t.Parallel()
	byHand := ProxyConfig{HTTPSProxy: "ftp://ir:s3cret@proxy.corp:2121", HTTPProxy: "gopher://proxy.corp:70"} //nolint:gosec // G101: deliberate, see above.

	assert.Empty(t, proxyFor(t, byHand, "https://edr.example.com:8443"))
	assert.Empty(t, proxyFor(t, byHand, "http://edr.example.com:8080"))
}

// The convenience that must not regress: a value written with no scheme at all is read as HTTP, by the resolver and therefore
// by this. Classifying a second parse of the same string is what would break it.
func TestAProxyWrittenWithoutASchemeIsStillReadAsHTTP(t *testing.T) {
	t.Parallel()
	cfg, err := loadFrom(layeredGetenv(
		map[string]string{ //nolint:gosec // G101: the credential in this URL is the input under test: it must never leave the agent.
			"EDR_SERVER_URL": "https://edr.example.com:8443",
			"HTTPS_PROXY":    "proxy.corp:3128",
		},
		func(string) (string, bool) { return "", false },
	))
	require.NoError(t, err)

	assert.Empty(t, cfg.Proxy.Refused, "this is a proxy the agent speaks, spelled the short way")
	assert.Equal(t, "http://proxy.corp:3128", proxyFor(t, cfg.Proxy, "https://edr.example.com:8443"))
}

// Every scheme the agent does speak, with credentials, unchanged.
//
// spec:agent-configuration/a-proxy-the-agent-cannot-speak-is-refused-rather-than-used/a-supported-proxy-is-unaffected
func TestASupportedProxyIsUnaffected(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"http://user:secret@proxy.corp:3128",
		"https://user:secret@proxy.corp:3129",
		"socks5://user:secret@proxy.corp:1080",
		"socks5h://user:secret@proxy.corp:1080",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			cfg, err := loadFrom(layeredGetenv(
				map[string]string{"EDR_SERVER_URL": "https://edr.example.com:8443", "HTTPS_PROXY": value},
				func(string) (string, bool) { return "", false },
			))
			require.NoError(t, err)

			assert.Empty(t, cfg.Proxy.Refused)
			assert.True(t, cfg.Proxy.Set())
			assert.Equal(t, value, proxyFor(t, cfg.Proxy, "https://edr.example.com:8443"))
		})
	}
}

// The list is one list. The control channel's tunnel dispatch asks this rather than keeping the copy it used to, so a scheme
// added on one side and not the other cannot produce a proxy that one path dials and another refuses.
func TestProxySchemeSupported(t *testing.T) {
	t.Parallel()
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		assert.True(t, ProxySchemeSupported(scheme), "%s is a proxy the agent speaks", scheme)
	}
	for _, scheme := range []string{"ftp", "gopher", "socks4", "ssh", "", "HTTP"} {
		assert.False(t, ProxySchemeSupported(scheme), "%s is not, and must not be dialed", scheme)
	}
}
