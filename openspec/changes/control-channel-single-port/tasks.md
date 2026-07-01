## 1. Spec delta and decision

- [x] 1.1 This proposal plus spec deltas pass `openspec validate control-channel-single-port --strict`
- [x] 1.2 Record the cmux rejection and the ServeHTTP shutdown rework in `design.md`

## 2. Server: multiplex on the main listener

- [x] 2.1 Dispatch `application/grpc` HTTP/2 requests to the control gateway and all others to the REST/UI handler, in one native HTTP/2 server (`httpserver.RunAndShutdown`)
- [x] 2.2 Enable cleartext HTTP/2 (h2c) in the TLS-terminated-by-proxy mode; rely on ALPN for the TLS mode
- [x] 2.3 Build the gateway without transport credentials and serve it via `grpc.Server.ServeHTTP`; drop the separate listener and `EDR_CONTROL_ADDR`
- [x] 2.4 Rework `Gateway.Stop` to cancel live streams (no `grpc.GracefulStop`, which panics under `ServeHTTP`); shutdown is driven by `http.Server.Shutdown`
- [x] 2.5 Unit test: gRPC + HTTP/1.1 + HTTP/2 (including a reused HTTP/2 connection) coexist on one listener, TLS and plaintext; bidirectional control stream over net/http's HTTP/2

## 3. Agent: derive the endpoint, always on

- [x] 3.1 Derive the control endpoint from `EDR_SERVER_URL` (host:port, scheme-based transport security); remove `EDR_CONTROL_ADDR`
- [x] 3.2 Attempt the channel unconditionally (no enabling flag); keep the short-poll as the fallback
- [x] 3.3 Unit test for the server-URL-derived dial target and credentials

## 4. Deployment

- [x] 4.1 Quickstart Caddy reverse-proxies to the upstream over h2c so the control stream is forwarded
- [ ] 4.2 Validate the proxied control stream on the notarized RC (covered by the agent/extension RC re-test, #557)
