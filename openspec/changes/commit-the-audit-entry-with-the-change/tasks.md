# Tasks

- [x] Add `rule_content_audit_outbox` and write entries into the transactions that make the change: document put, document delete, and pack rollback.
- [x] Keep the payload opaque to rulecontent, and build it from a callback so it carries facts only that layer knows.
- [x] Drain entries into the audit recorder on the request that wrote them, and on a sweep for the ones it could not.
- [x] Give the payload an explicit tagged shape rather than marshalling the domain type, so a field rename elsewhere cannot change a persisted format.
- [x] Require the outbox at construction, on the same terms as the recorder: a wiring whose entries go nowhere must not be constructible.
- [x] Pin the atomicity against real MySQL, in both directions, and mutation-test the transactional enqueue.
