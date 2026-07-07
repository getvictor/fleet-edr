# Design: serve the control channel on the main port

This records the transport and shutdown decisions behind `control-channel-single-port`. The spec deltas state observable behavior; this document records how it is realized and the alternative that was rejected.

## Multiplex by content-type on one native HTTP/2 server

`server/httpserver.RunAndShutdown` wraps the REST/UI handler: when a control gateway is supplied, requests with `r.ProtoMajor == 2` and an `application/grpc` content type are dispatched to the gateway's `grpc.Server.ServeHTTP`, and all others to the original handler. Over TLS, `ListenAndServeTLS` negotiates HTTP/2 via ALPN; in the TLS-terminated-by-proxy mode the server sets `http.Server.Protocols` to enable HTTP/1.1 plus cleartext HTTP/2 (h2c) so a front proxy can forward gRPC on the same upstream. The gateway's gRPC server carries no transport credentials of its own (TLS is terminated upstream) and keeps only its stream interceptor (host-token auth) and stats handler (OTel propagation).

The agent derives its dial target from `EDR_SERVER_URL`: `host:port` (defaulting the port to the scheme's standard), with `credentials.NewTLS(pinnedConfig)` for `https` and insecure credentials for `http`. This is the same host, port, and transport security as the REST client.

## Rejected: a connection multiplexer (cmux)

The first implementation used `cmux` to split gRPC from REST by sniffing the connection's opening HTTP/2 frames for the `application/grpc` content type. It was rejected: `cmux`'s HTTP/2 header matcher injects a SETTINGS frame while sniffing, which corrupts persistent HTTP/2 connections that do not match. In dev-server testing every real agent's REST poll connection failed with `http2: PROTOCOL_ERROR` after the first request. Dispatching inside one native HTTP/2 server avoids sniffing entirely: net/http owns the HTTP/2 framing and the handler only reads an already-parsed request header. A unit test pins multi-request reuse over a single HTTP/2 connection so this regression cannot return.

## Shutdown without grpc GracefulStop

Because the gateway is served via `grpc.Server.ServeHTTP` (riding net/http's HTTP/2 server), `grpc.Server.GracefulStop` is unusable: its `serverHandlerTransport` has no `Drain`, so GracefulStop panics. Shutdown is instead driven by `http.Server.Shutdown`, with the gateway cancelling its live streams so their handlers return promptly: `Gateway.Stop` marks the gateway closing (a connection accepted mid-shutdown is rejected) and cancels every registered connection's context. The control streams are long-lived and would otherwise hold `http.Server.Shutdown` open until its deadline. The agent's keep-alive PINGs need no special server policy: net/http's HTTP/2 server answers them without gRPC's strict ping-flood GOAWAY, so the previous keepalive-enforcement option is dropped.

## Per-stream deadlines cleared for the control channel

Sharing the REST `http.Server` means the control stream inherits its per-request `ReadTimeout` and `WriteTimeout`. On an HTTP/2 stream those bound the whole request/response, not one message, so a 10s `ReadTimeout` tears the long-lived stream down every 10s (observed in live QA as a ~10s reconnect flap, and in SigNoz as a run of 10s `ControlChannel/Connect` spans ending in `i/o timeout`). The multiplexer clears both deadlines for the `application/grpc` branch via `http.NewResponseController` (`SetReadDeadline`/`SetWriteDeadline` to the zero time) before delegating to the gateway; the REST and UI surface keeps its timeouts. Delivery still degrades safely if a transport ever refuses the clear: the agent reconnects and the retained short-poll remains the floor, so no command is lost.

## Deployment

In the quickstart / single-VM model a front proxy (Caddy) terminates the public TLS and reverse-proxies to the server's plaintext port. The proxy SHALL forward to the upstream over HTTP/2 cleartext (h2c) so the bidirectional control stream is carried, not just HTTP/1.1 REST. The server's plaintext mode accepts h2c for exactly this.
