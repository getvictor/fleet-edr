# Tasks

- [x] Make attribution total in `server/rules/api`: add `ProjectOrigin` and `UnknownOrigin`, and have `OriginOf` return one of them rather than an empty string.
- [x] Add the `origin` column to `alerts` (migration 00012), forward-only and with no backfill.
- [x] Stamp attribution onto the alert in the engine, read from the rule beside its declared mode and threaded through routing to persistence, so a finding cannot carry its own credit.
- [x] Carry the column through the store's insert, both alert reads, and the webhook delivery projection.
- [x] Carry each imported rule's upstream `references` into its documentation.
- [x] Surface `origin` on the alert list and the alert breadcrumb as rendered text, and `references` on the rule documentation page.
- [x] Render a reference as a link only for an `http` or `https` scheme; display anything else inert.
- [x] Describe the new `origin` and `references` fields in the OpenAPI schema and regenerate the embedded copy.
- [x] Pin the attribution constants to their literals, since a test comparing output against the constant cannot see the constant become wrong.
- [x] Integration test: attribution reaches the persisted alert, differs correctly between a vendored and an authored rule, and survives the rule being re-credited afterwards.
- [x] Confirm on a running server that a promoted vendored rule's alert displays its author end to end.
