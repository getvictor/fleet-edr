# 0019. TLS 1.3 only, with no TLS 1.2 opt-out

- Status: Accepted
- Date: 2026-08-21
- Deciders: getvictor

## Context

Every network boundary this product owns is a boundary between components we also own or specify: the agent (our Go binary), the browser UI (evergreen Chrome / Safari / Firefox / Edge), and service-account API clients written against our OpenAPI document. There is no third-party integrator dialling us with a fixed old TLS stack, no embedded appliance, and no long-tail of unknown clients, because the product is macOS 13+ only (with Windows 11 24H2+ planned per ADR-0018) and both those platforms ship TLS 1.3 in their system stacks.

The usual reason a server keeps a TLS 1.2 floor is compatibility with clients it cannot upgrade. We do not have that population. The usual cost of keeping one is not theoretical either: TLS 1.2 brings a cipher-suite selection surface (which suites, in which order, with which curves), and every one of those is a configuration knob that can be set wrong, must be reviewed, and shows up in scanner output. TLS 1.3 removes the question by negotiating from a fixed list that Go does not expose for override.

An earlier revision of the threat model described the server as "TLS 1.2 with restricted AEAD suites". That was corrected on 2026-07-05 to match the code, which had already moved to a 1.3 floor. This ADR exists because the decision itself was never written down: it lived in a code comment, a `best-practices.md` checkbox, and a threat-model cell, none of which record why.

## Decision

The server enforces `MinVersion: tls.VersionTLS13` unconditionally (`server/httpserver/tls.go`), and ships **no** environment variable, flag, or config key to lower it. No `CipherSuites` override is set, because TLS 1.3 does not take one.

The single sanctioned way to terminate anything older is `EDR_TLS_TERMINATED_BY_PROXY=1`, which makes the server listen in plaintext on its bind address so an operator-run front proxy owns TLS. That mode logs a warning at startup and is only safe when the bind address faces the proxy alone, never agents or the internet.

## Consequences

**Easier.** There is no cipher-suite policy to maintain, review, or explain to an auditor, and no downgrade path to test. The threat model's tampering row reduces to one sentence. A scanner finding about weak TLS 1.2 suites cannot apply to us, because there is no TLS 1.2.

**Harder, and this is the real cost.** Any future client that cannot do TLS 1.3 cannot talk to us at all, and the failure is an opaque handshake error rather than a negotiated downgrade. Concretely, that would bite a customer fronting us with an old load balancer, a corporate TLS-inspection middlebox pinned to 1.2 (common in exactly the enterprises this product targets), or a partner integration written in an old runtime. The escape hatch for all three is `EDR_TLS_TERMINATED_BY_PROXY`, which is a real answer but a worse one: it moves the trust boundary to a component we do not ship and cannot verify.

**Known inconsistency, deliberate.** `server/cmd/fleet-edr-demo-seed/seed.go` sets a `tls.VersionTLS12` floor on its own outbound client. That is a client-side floor in a demo-seeding tool, not a server listener, and it is moot against our own server, which will only ever offer 1.3. It is left alone rather than churned.

## Alternatives considered

**TLS 1.2 floor with a restricted AEAD suite list.** The conventional posture, and what the threat model used to claim. Rejected because it buys compatibility with a client population we do not have, and pays for it with a permanent configuration surface. If the population ever appears, the proxy mode covers it without reopening the listener.

**A `EDR_TLS_MIN_VERSION` knob defaulting to 1.3.** Superficially the flexible choice. Rejected on the same grounds the `config-surface-review` maintenance task applies generally: a knob that no operator sets is parse, validate, document and test surface for nothing, and this particular knob's only function would be to let an operator quietly weaken the transport of a security product. A downgrade should require a deliberate architectural act (front a proxy), not an environment variable.

**mTLS to the agent instead of bearer tokens.** Out of scope here and tracked separately; the agent-to-server boundary is a per-host signed bearer token over server-side TLS (see the threat model and ADR-0013). This ADR governs the transport floor only, not the authentication scheme.
