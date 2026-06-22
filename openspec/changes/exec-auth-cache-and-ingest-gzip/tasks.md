# Tasks

## #209 Exec-auth result caching

- [x] Add pure `authResultIsCacheable(AuthDecision) -> Bool` (decided ALLOW cacheable; undecided + DENY not).
- [x] `dispatchAuthDecision` responds with the computed cache flag; self-allow failsafe responds `cache: true`.
- [x] `ApplicationControlStore.onSnapshotApplied` hook fired on every accepted apply; wired to `es_clear_cache` in ESFSubscriber.
- [x] Scrub the stale `.allow` doc comment that said the result is not cached.
- [x] Unit tests: cacheability mapping + store flush-on-accept / no-flush-on-reject.
- [ ] VM QA: tight-loop exec of an allowed binary shows far fewer handler entries; a policy push flushes the cache.

## #405 gzip request compression

- [ ] Agent gzips the body + sets `Content-Encoding: gzip` in `uploader.doUpload`.
- [ ] Server decompresses on `Content-Encoding: gzip`, caps the decompressed stream, rejects corrupt gzip distinctly; plaintext path preserved.
- [ ] Unit tests: gzip accepted, plaintext accepted, decompression bomb -> 413, corrupt gzip -> error.
- [ ] VM QA: agent uploads are gzip on the wire and ingest succeeds.

## Gates

- [ ] `go test ./agent/uploader/... ./server/detection/...`
- [ ] Swift logic tests (EDRExtensionLogicTests).
- [ ] `task lint:go`, `task lint:dashes`, `openspec validate --all --strict`.
