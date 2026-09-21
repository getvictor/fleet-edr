# A single sign-on save can name the configuration it was editing

Issue #1046. `PUT /api/settings/sso` replaces the whole configuration. A page left open, or a script that read the settings earlier, silently overwrites anything saved since: the issuer, client id, scopes, default role, external URL and the group mapping. The only race refused today is between the server's own read and its write, within one request, which does nothing for the operator whose page has been open for ten minutes.

Review of #1042 worked through adding a version check and found each piece a first attempt misses. Those findings are the requirements this implements.

## What changes

- **The read and the save both report a version**, and a save may send one back to be refused if anything changed since. Omitting it overwrites, which is what a script that means to set the configuration outright asks for: the check is opt-in so automation does not have to read before it can write.
- **One version covers both stored parts.** The OIDC configuration and the deployment settings holding the external URL are separate documents with separate counters, so checking one leaves the other open. The version names both, and either moving supersedes it.
- **Both parts are read from one transaction**, on the read and on the save's response. Two separate reads can be landed between, which pairs one part's new version with the other's old value; a client sending that version back would pass the check while holding stale data.
- **A first save has a defined winner.** With nothing stored there is no row to lock, and what a `SELECT ... FOR UPDATE` takes in its place is a gap lock whose behaviour depends on the isolation level. Each document is created with a plain insert instead, so the second of two racing first saves loses on the primary key and is told, rather than silently replacing the first.

## What this does not claim

The two counters move together today, because every save writes both documents. The composite is what keeps that from being load-bearing: `app_config` is the deployment's general settings document by design, and whatever settings surface lands there next moves its counter alone.

For the same reason, the two first-save guards are individually redundant today: either document's insert is enough to decide the race, and removing one leaves the behaviour correct. They are kept as a pair because each is simply the correct write for "create this, expecting none", and because which one decides depends on which document happens to exist.

## Out of scope

- The page sending what it read, and saying on a conflict that nothing was saved. That is the consumer half and follows in its own change.
- Any other setting in the deployment settings document. There is one today.
