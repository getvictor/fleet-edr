# Tasks

- [x] Reading pack status is authorized as a read, because it changes nothing, and reports whether the deployment is current rather than leaving a reader to compare two digests.
- [x] `can_roll_back` is stated rather than derived from the previous digest by each caller. "Can I undo this" is the question someone looking at a bad pack is asking, and two surfaces deriving it separately would eventually derive it differently.
- [x] Rolling back requires a reason, on the same footing as every other change to rule content and with the strongest case for it: the change swaps out every shipped detection at once.
- [x] The rollback records its own audit action rather than reusing a document change, because an audit trail that called this a document edit would understate a change to every shipped rule.
- [x] A refused rollback writes no audit row, since nothing happened to the thing being audited, and that is asserted rather than assumed.
- [x] Withheld shipped rules reach both the response and the audit payload. The deployment is deliberately not running content it was offered, the operator's own rule is why, and nothing else would tell them or a later reviewer.
- [x] Nothing retained is a conflict rather than a server error: the operator asked for something that does not exist yet rather than something that went wrong, and a 500 would send them looking for a fault that is not there.
- [x] The pack lifecycle is a port `rulecontent` declares and `rules` consumes, bound to the build's own corpus in `cmd/main`. That binding is what lets both methods take no arguments, and it keeps `rulecontent` importing nothing from `rules`.
- [x] The routes are in the integration mux's allow-list. That list forwards explicitly, so a route missing from it 404s while looking mounted, which this repository has seen before.
- [x] Both routes are documented in the OpenAPI spec, and the drift guard confirmed the served copy stayed in sync.
- [x] Real-tool QA over HTTP on the dev server. On a current deployment the status reported `current=true`, matching digests and `can_roll_back=false`, and a rollback was refused 409 with nothing retained and 400 with no reason. After a deliberately stale pack was planted and the startup install replaced it, the status reported `can_roll_back=true`, the rollback returned 200 with the restored digest and version 29, the older generation's content was back in the corpus, and the audit row named the operator and their reason.
- [x] The empty difference lists marshalled as `null` rather than `[]`, which reading the real response is what surfaced. Fixed and pinned: a nil slice makes every consumer null-check before iterating, and makes "no rules changed" look like a missing field.
