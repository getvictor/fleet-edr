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
		map[string]string{
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
		map[string]string{
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
