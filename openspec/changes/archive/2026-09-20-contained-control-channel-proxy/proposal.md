# A contained host's control channel reaches a proxy it cannot resolve

Issue #1064. On a contained host whose agent reaches the server through an HTTP proxy named by host name, the gRPC control channel cannot reconnect while the host is contained.

The agent pins the lifeline addresses for every other server connection, but it hands the control channel to gRPC's own proxy support, because a custom context dialer replaces that support rather than adding to it. gRPC then resolves the proxy's name with the system resolver, and on a contained host `mDNSResponder` sends no query, so the lookup finds nothing. The lifeline allows the proxy's addresses and the agent's HTTP transport reaches it through them; only this one connection could not.

The effect was not an outage: with no stream the commander falls back to polling every five seconds through the HTTP transport, so commands still arrive. What an operator saw was slower delivery and a console reporting the stream disconnected for as long as the host stayed contained.

## What changes

The control channel dials the proxy itself and tunnels through it, so gRPC resolves nothing. The dial to the proxy goes through the containment manager, which is what pins it to the lifeline addresses; the server is named only inside the tunnel request, where no resolver is involved. Credentials configured on the proxy's own address are presented on that request, the way the agent's other traffic through the same proxy already presents them.

A proxy that refuses the tunnel fails the connection. Returning a connection that carries the proxy's error page instead would leave gRPC running TLS over it and reporting something further from the cause.

## Note for the next reader

The response to the tunnel request has to be read with a buffered reader, and a buffered reader takes whatever the socket has ready, which can include the first bytes the tunnel itself carries. Those bytes are kept and handed to the caller rather than dropped with the reader. Dropping them is silent, and silent here means the channel hangs rather than fails, on a path that runs only while a host is contained.
