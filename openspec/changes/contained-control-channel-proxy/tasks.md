# Tasks

- [x] Dial the proxy through the containment manager and tunnel to the server, so gRPC resolves neither.
- [x] Dial the proxy at the address the lifeline pins for it, rather than composing one from the URL and risking a different default port.
- [x] Take the dial over only for a proxy whose protocol this build speaks, leaving the rest exactly as they were.
- [x] Present the credentials the proxy's configured address carries, as the agent's other traffic through it does.
- [x] Fail the connection when the proxy refuses the tunnel, rather than returning one that carries its error page.
- [x] Keep the bytes the tunnel carried before the response was fully read, rather than dropping them with the reader.
- [x] Exercise on a live macOS VM: contain a host whose proxy is named by host name, and confirm the control channel reconnects.
