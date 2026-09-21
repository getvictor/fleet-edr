# A contained host reconnects through a SOCKS or HTTPS proxy too

Issue #1110. #1064 took the control channel's dial over from gRPC and tunnelled it through the proxy at its pinned lifeline address, which is what its VM run exercised, but only for an HTTP proxy. `containment.TargetFor` already derives a lifeline target for `socks5`, `socks5h` and `https`, so those deployments are configurable today and were left dialing exactly as before: the channel stays down while the host is contained and commands arrive only by polling. A contained host is when the control channel matters most.

## What changes

- **SOCKS5, in its own protocol.** A SOCKS proxy needs a handshake rather than a CONNECT. The handshake is `golang.org/x/net/proxy`'s rather than hand-written: a SOCKS5 client is a small protocol that is easy to get subtly wrong, and the wrong version of it in an agent running as root is not worth the lines saved. The library is handed a dialer that reaches the proxy's pinned address instead of resolving its name, which is what puts the connection on the lifeline.
- **The destination crosses as a name, for both `socks5` and `socks5h`.** Plain `socks5` nominally means the client resolves first, which is the one thing that certainly fails on a contained host and is the failure this removes. Treating both as remote-resolving is the only behaviour that works there, and the delta says so rather than leaving it implied.
- **HTTPS proxies over TLS, before any bytes.** The CONNECT carries the operator's Basic credentials, so the handshake has to come first. The configuration is the agent's own, cloned, with only `ServerName` set to the proxy's name.
- **The opt-in shape is kept.** `tunnelable` still enumerates the schemes it speaks. net/http returns whatever is in the environment, `ftp://proxy` included, so a default branch would eventually be handed a scheme nobody considered and would write the operator's credentials into a protocol that cannot parse them.

## Why the TLS configuration is the agent's own rather than a strict one

This is the part worth disagreeing with if anyone is going to. Cloning the agent's configuration means a deployment that sets a server fingerprint applies that fingerprint to the proxy's certificate too, which will fail. That is not an oversight: `net/http` does exactly the same for an https proxy, so the agent's uploads and polls already fail in that deployment, and the control channel now fails identically instead of differently.

The alternative, a fresh strict configuration, is worse in the way that matters. It would reject a private-CA proxy certificate that the agent's own transport accepts, so uploads and polling would keep working while only the control channel failed. That presents as the bug this change exists to fix, and would be diagnosed as one.

## Out of scope

- SOCKS4, and any scheme beyond the four now enumerated. They stay dialed as they were.
- Making the proxy's own TLS policy configurable separately from the server's. If a deployment needs that, it needs it for uploads first.
