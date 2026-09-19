package config

import (
	"net/http"
	"net/url"

	"golang.org/x/net/http/httpproxy"
)

// ProxyConfig is the outbound proxy the agent reaches the server through, as the three variables an operator sets.
//
// It is read through the same layered lookup as every other setting, which is the whole point of it existing (issue #1117). The
// agent used to take its proxy from http.ProxyFromEnvironment, which reads the REAL process environment, while the launchd
// plist tells the reader that all tunables come from /etc/fleet-edr.conf. So an operator who put HTTPS_PROXY in that file got no
// proxy at all, silently, and nothing in the operator docs said where else to put it.
//
// The variables keep their conventional names rather than gaining an EDR_ prefix: an operator configuring a proxy already knows
// these, every other tool on the host reads them, and a deployment that sets them in the environment must keep working.
type ProxyConfig struct {
	// HTTPProxy is HTTP_PROXY (or http_proxy), used for an http server URL.
	HTTPProxy string
	// HTTPSProxy is HTTPS_PROXY (or https_proxy), used for an https server URL, which is the production posture.
	HTTPSProxy string
	// NoProxy is NO_PROXY (or no_proxy): the hosts reached directly.
	NoProxy string
}

// loadProxy reads the proxy variables through getenv, uppercase first then lowercase, which is the order net/http itself uses.
func loadProxy(getenv func(string) string) ProxyConfig {
	pick := func(names ...string) string {
		for _, name := range names {
			if v := getenv(name); v != "" {
				return v
			}
		}
		return ""
	}
	return ProxyConfig{
		HTTPProxy:  pick("HTTP_PROXY", "http_proxy"),
		HTTPSProxy: pick("HTTPS_PROXY", "https_proxy"),
		NoProxy:    pick("NO_PROXY", "no_proxy"),
	}
}

// Set reports whether any proxy is configured at all, so a caller can say so once at startup rather than leaving an operator to
// infer it from traffic that does or does not appear on their proxy.
func (p ProxyConfig) Set() bool {
	return p.HTTPProxy != "" || p.HTTPSProxy != ""
}

// ProxyFunc returns the proxy chooser for every outbound connection the agent makes to the server: its uploads and polling, its
// enrollment and token refresh, the containment lifeline's target, and the control channel.
//
// All of them, deliberately. A proxy that applied to some of the agent's traffic and not the rest is worse than one that applies
// to none: the parts that work hide the parts that do not, and the containment lifeline would be pinned to an address the rest
// of the agent was not using.
//
// The rules are x/net/http/httpproxy's, the same package net/http builds ProxyFromEnvironment on, so the scheme handling and the
// NO_PROXY matching are the ones an operator already expects rather than a second interpretation of the same variables.
func (p ProxyConfig) ProxyFunc() func(*http.Request) (*url.URL, error) {
	// Built once here rather than per request: ProxyFunc parses NoProxy and caches the result, and the caller holds what this
	// returns for the life of the transport.
	chooser := (&httpproxy.Config{
		HTTPProxy:  p.HTTPProxy,
		HTTPSProxy: p.HTTPSProxy,
		NoProxy:    p.NoProxy,
	}).ProxyFunc()
	return func(req *http.Request) (*url.URL, error) {
		return chooser(req.URL)
	}
}
