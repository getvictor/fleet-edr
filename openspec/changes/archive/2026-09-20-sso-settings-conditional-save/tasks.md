# Tasks

- [x] Report a version on the read and on the save, covering both stored parts, from one transaction each.
- [x] Accept a version on the save, refuse it with a conflict when either part has moved on, and write nothing.
- [x] Keep a save that names no version an overwrite, so automation need not read first.
- [x] Give two racing first saves a defined winner, without depending on the isolation level.
- [x] Refuse a version the server did not issue, rather than reading it as absent and overwriting.
- [x] The page sends what it read and reports a conflict. Landed separately, in `sso-settings-conflict-page`.
