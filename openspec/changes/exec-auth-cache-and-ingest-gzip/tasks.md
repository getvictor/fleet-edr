# Tasks

## #209 Exec-auth result caching

- [x] Add pure `authResultIsCacheable(AuthDecision) -> Bool` (decided ALLOW cacheable; undecided + DENY not).
- [x] `dispatchAuthDecision` responds with the computed cache flag; self-allow failsafe responds `cache: true`.
- [x] `ApplicationControlStore.onSnapshotApplied` hook fired on every accepted apply; wired to `es_clear_cache` in ESFSubscriber.
- [x] Scrub the stale `.allow` doc comment that said the result is not cached.
- [x] Unit tests: cacheability mapping + store flush-on-accept / no-flush-on-reject.
- [ ] VM QA: tight-loop exec of an allowed binary shows far fewer handler entries; a policy push flushes the cache.

## #405 gzip request compression

- [x] Agent gzips the body + sets `Content-Encoding: gzip` in `uploader.doUpload`.
- [x] Server decompresses on `Content-Encoding: gzip`, caps the decompressed stream, rejects corrupt gzip distinctly; plaintext path preserved.
- [x] Unit tests: gzip accepted, plaintext accepted, decompression bomb -> 413, corrupt gzip -> error.
- [x] VM QA: agent uploads are gzip on the wire and ingest succeeds (edr-dev, 2026-06-22: real agent end-to-end + curl A/B).

## Gates

- [x] `go test ./agent/uploader/... ./server/detection/...`
- [x] Swift logic tests (EDRExtensionLogicTests).
- [x] `task lint:go`, `task lint:dashes`, `openspec validate --all --strict`.
