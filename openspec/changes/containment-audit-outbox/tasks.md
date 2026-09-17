# Tasks

- [x] Add `containment_audit_outbox` to the response migration corpus.
- [x] Move `auditoutbox` out of the rules context and take its table as a constructor argument.
- [x] Carry `remote_addr` through the outbox encoding.
- [x] Write the containment change's audit entry inside the transaction that records the state and queues its command.
- [x] Deliver the entry after the commit, and sweep the ones a request could not deliver.
- [x] Cover a recorder that is down for the change and back for the delivery, and a refused change leaving no entry.
