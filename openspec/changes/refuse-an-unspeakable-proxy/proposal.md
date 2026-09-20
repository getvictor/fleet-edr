# A proxy the agent cannot speak is refused, not used

Issue #1128. An operator who configures a proxy with a scheme the agent does not support still has the agent connect to that host and send the configured credentials in clear text, as HTTP Basic, before finding out it cannot talk to it.

Measured on edr-dev while completing the QA owed by #1110. With `HTTPS_PROXY=ftp://qauser:qasecret@proxy-qa.local:2122`, a listener that answers nothing received four connections in twenty-five seconds, each carrying:

```
CONNECT 192.168.64.1:8089 HTTP/1.1
Proxy-Authorization: Basic cWF1c2VyOnFhc2VjcmV0
```

That base64 is `qauser:qasecret`. The connections repeat on every retry for as long as the setting stands.

The control channel is not the source and behaves correctly: `tunnelable` recognises four schemes and anything else keeps gRPC's own dialing, so the channel connected directly and never touched the listener. The leak is `net/http`'s, which decides how to reach a proxy from the TARGET's scheme rather than the proxy's: for an `https` target it performs a plaintext `CONNECT` to whatever host the proxy URL names, attaching `Proxy-Authorization` from its user info, for any proxy scheme that is not `socks5`. `x/net/http/httpproxy`, which chooses the proxy, does no scheme validation at all.

## What changes

- **The scheme is checked where the agent resolves its proxy**, in `agent/config`, so every consumer gets the same answer: the HTTP transport, the control channel, and the containment lifeline target, which is derived from the same proxy URL and would otherwise pin a host the agent never dials.
- **A setting the agent cannot speak is dropped at load**, so no field of `ProxyConfig` ever holds a proxy that will not be used, and `Set()` does not claim one is configured.
- **`ProxyFunc` refuses one too.** That is what makes it an invariant rather than a convention: a `ProxyConfig` built by hand, by a caller that does not go through the loader, still cannot hand an unspeakable proxy to a dialer.
- **The operator is told once at startup**, by a warning naming the setting, the scheme and what the agent did instead.
- **One list, not three.** `config.ProxySchemeSupported` is now the single answer to which schemes the agent speaks, and the control channel's `tunnelable` asks it rather than carrying its own copy.

## Decided here: refuse the proxy, do not refuse to start

The issue left this open, and the two candidates pull in opposite directions.

Refusing to start matches how this package already treats a malformed `EDR_SERVER_URL`, which is a startup error. It also removes any chance of quietly sending traffic somewhere the operator did not intend.

The agent connects directly instead, for three reasons. A host whose agent will not start is an unmonitored host, and for an endpoint product that is the more dangerous failure of the two: a typo in one conf-file line would take a fleet dark. The traffic in question only ever goes to the agent's own configured server, so "bypassing the proxy" means the agent's own telemetry reaching its own server rather than anything being exfiltrated anywhere new. And it is what the control channel already does with the same input, so the agent behaves one way rather than two.

It is also never worse operationally than today. Where the network genuinely requires the proxy, the direct connection fails and the agent retries, which is the same visible breakage the unsupported scheme already produces, minus the credential on the wire.

The difference from `EDR_SERVER_URL` is that a server URL has no fallback: there is nowhere else to connect. A proxy has one.

## Out of scope

- Adding support for any further proxy scheme. This is about what happens to one the agent cannot speak.
- Surfacing the refusal in the agent's health report as well as its log. The log line is what the issue asked for, and a config-health component is its own change.
