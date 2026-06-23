# Coalesce network and DNS telemetry before enqueue: tasks

## 1. Schema

- [ ] `schema/events.json`: add optional `coalesced_count` (integer, minimum 1) and `last_timestamp_ns` (integer) to `network_connect_payload` and `dns_query_payload`, documented as agent-side coalescing fields. `response_addresses` semantics extended to "union across the coalescing window".

## 2. Coalescer

- [ ] New package `agent/coalesce`: a windowed coalescer with `Handle(ctx, eventJSON []byte)` that buffers `network_connect`/`dns_query` by identity key and passes every other event straight to the enqueue callback. Earliest `timestamp_ns` wins; `coalesced_count` + `last_timestamp_ns` track the span; DNS `response_addresses` union. Payload patched losslessly via `map[string]json.RawMessage` (existing fields untouched). A single-occurrence representative is enqueued byte-for-byte unchanged.
- [ ] Flush goroutine on a window ticker; drains the buffer under a lock-swap (Enqueue happens outside the lock); final flush on `ctx.Done()`.
- [ ] Window `0` => disabled (pass-through), preserving today's behavior.

## 3. Config + wiring

- [ ] `agent/config/config.go`: `NetworkCoalesceWindow` from `EDR_NETWORK_COALESCE_WINDOW` (NonNegativeDuration, default 10s, 0 disables).
- [ ] `agent/cmd/fleet-edr-agent/main.go`: construct the coalescer, route `OnEvent`'s post-enrich/proctable data through `coalescer.Handle` instead of `q.Enqueue` directly; run the flush goroutine; flush on shutdown.

## 4. Spec

- [ ] `agent-event-queue` delta: ADDED "Pre-enqueue coalescing of repetitive network and DNS telemetry".

## 5. Docs

- [ ] `docs/operations.md`: document `EDR_NETWORK_COALESCE_WINDOW`, its default, the disable value, and the 30s-beacon-window constraint on raising it.

## 6. Tests

- [ ] `agent/coalesce` unit tests: identity-key merge (count, last_timestamp_ns, earliest envelope timestamp preserved); DNS response-address union; query+response merge; non-network passthrough is immediate and byte-identical; single-occurrence representative byte-identical; flush-on-shutdown emits buffered representatives; window=0 is full pass-through.
- [ ] PBT (`pgregory.net/rapid`) round-trip: for any sequence of same-key network/DNS events, the coalesced representative preserves the earliest timestamp, count == number merged, and the address union equals the set union of inputs.
- [ ] Efficacy corpus re-run: `dns_c2_beacon` and `suspicious_exec` still fire with coalescing enabled.

## 7. Verification

- [ ] `go build ./agent/...`; `go test ./agent/coalesce/... ./agent/config/...` green.
- [ ] gofmt, `task lint:go`, `openspec validate coalesce-network-dns-telemetry --strict`, markdown + dash lints.
- [ ] edr-dev VM: with coalescing on, confirm repeated curls to one host collapse to representative rows with `coalesced_count > 1` and detection still fires.
