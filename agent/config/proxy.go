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
	// Refused are the settings dropped because the agent cannot speak their scheme, for startup to report. The values
	// themselves are NOT carried: they hold the operator's proxy credentials, and this struct is logged and diffed.
	Refused []RefusedProxy
}

// RefusedProxy is one proxy setting the agent will not use, and why (issue #1128).
type RefusedProxy struct {
	// Setting is the variable's conventional upper-case name, which is what an operator searches their conf file for.
	Setting string
	// Scheme is what the agent could not speak, as the resolver read it.
	Scheme string
}

// supportedProxySchemes are the proxy protocols this agent can actually speak: a CONNECT tunnel to an HTTP or HTTPS proxy, and
// the SOCKS5 handshake for both of its spellings (issues #1064, #1110).
//
// This is the ONE answer to that question. The control channel's tunnel dispatch asks here rather than keeping the copy it used
// to, because the two disagreeing is how a proxy gets dialed by one path and refused by another, which is the shape of the bug
// this list exists to prevent.
var supportedProxySchemes = map[string]bool{"http": true, "https": true, "socks5": true, "socks5h": true}

// ProxySchemeSupported reports whether the agent can speak a proxy of this scheme.
//
// A scheme it cannot speak is not merely unusable: the agent's HTTP transport decides how to reach a proxy from the TARGET's
// scheme rather than the proxy's, so an unrecognised one is still sent a plaintext CONNECT carrying whatever credentials the
// operator put in the address. That is the leak this predicate exists to stop (issue #1128).
func ProxySchemeSupported(scheme string) bool { return supportedProxySchemes[scheme] }

// loadProxy reads the proxy variables through getenv, uppercase first then lowercase, which is the order net/http itself uses,
// and drops any whose scheme the agent cannot speak.
//
// Dropping at load means no field here ever holds a proxy that will not be used, so Set() does not claim one is configured and
// no consumer has to ask a second question about a value it was handed.
func loadProxy(getenv func(string) string) ProxyConfig {
	pick := func(names ...string) string {
		for _, name := range names {
			if v := getenv(name); v != "" {
				return v
			}
		}
		return ""
	}
	p := ProxyConfig{NoProxy: pick("NO_PROXY", "no_proxy")}
	p.HTTPProxy = p.keepSpeakable("HTTP_PROXY", pick("HTTP_PROXY", "http_proxy"), "http", &p.Refused)
	p.HTTPSProxy = p.keepSpeakable("HTTPS_PROXY", pick("HTTPS_PROXY", "https_proxy"), "https", &p.Refused)
	return p
}

// keepSpeakable returns value when the agent can speak the proxy it names, and "" otherwise, recording the refusal.
//
// target is the scheme of the traffic the setting governs, which is what decides how the resolver reads the value.
func (p ProxyConfig) keepSpeakable(setting, value, target string, refused *[]RefusedProxy) string {
	resolved := resolveProxyURL(value, target)
	if resolved == nil || ProxySchemeSupported(resolved.Scheme) {
		// Nothing configured, or something the agent speaks. An unparseable value yields nothing here and is left to the
		// resolver to report at the point of use, which is where it already reported it.
		return value
	}
	*refused = append(*refused, RefusedProxy{Setting: setting, Scheme: resolved.Scheme})
	return ""
}

// resolveProxyURL returns the proxy URL the resolver reads value as for traffic of the given scheme, or nil when it names none.
//
// Resolved THROUGH httpproxy rather than parsed here, deliberately. That package is what will actually choose the proxy, and it
// carries a convenience worth keeping: a value written without a scheme, `proxy.corp:3128`, is read as HTTP. Classifying a
// second parse of the same string would eventually disagree with the one that decides, and the disagreement would be a setting
// this refuses and the transport still dials, or the reverse.
func resolveProxyURL(value, scheme string) *url.URL {
	if value == "" {
		return nil
	}
	cfg := &httpproxy.Config{}
	if scheme == "https" {
		cfg.HTTPSProxy = value
	} else {
		cfg.HTTPProxy = value
	}
	// The host is a placeholder: NoProxy is empty here, so nothing about it can change which proxy comes back.
	resolved, err := cfg.ProxyFunc()(&url.URL{Scheme: scheme, Host: "proxy-scheme-probe.invalid"})
	if err != nil {
		return nil
	}
	return resolved
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
		resolved, err := chooser(req.URL)
		if err != nil || resolved == nil {
			return resolved, err
		}
		// Refused here as well as at load, and that is not belt and braces: this is what makes it an invariant rather than a
		// convention. The loader is one way a ProxyConfig comes into being; a caller that builds one directly, in production
		// or in a test that later becomes production, would otherwise hand a dialer a proxy the agent cannot speak, and the
		// transport would send it the operator's credentials before finding out (issue #1128).
		if !ProxySchemeSupported(resolved.Scheme) {
			return nil, nil
		}
		return resolved, nil
	}
}
