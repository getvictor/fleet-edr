# Tasks

- [x] Extend the scheme opt-in to `https`, `socks5` and `socks5h`, keeping it an enumeration rather than a default branch.
- [x] Speak SOCKS5 through `golang.org/x/net/proxy`, dialing the proxy at its pinned lifeline address and handing over the server as a name.
- [x] Offer the proxy URL's credentials in the SOCKS5 handshake.
- [x] Handshake TLS with an `https` proxy before writing the CONNECT, using the agent's own policy cloned with the proxy's name.
- [x] Tests: the SOCKS5 tunnel and its credentials, TLS before the CONNECT asserted on the bytes, a rejected certificate naming the proxy, and verification against the proxy's own name rather than the address it was pinned to.
- [x] Mutation-check each guard.
- [ ] Exercise on a live macOS VM as #1064 was: a contained host behind a SOCKS5 proxy, and behind an HTTPS proxy.
