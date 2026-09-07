# Make context registration checkable instead of remembered

## Why

`observability` ships migrations and exports a schema applier, and was absent from the standalone migrator's list. Nothing was broken on a server that started successfully, because the server applies that schema itself at boot. What was broken is the workflow the migrator exists for:

- A deployment that migrates as a privileged step and then runs the app without DDL grants failed at boot, on that one context.
- A multi-replica boot had every replica racing goose for it, which is the race a separate migrator removes.
- The CLI exited **0** having applied seven of eight contexts, so it did not do what its name says and said nothing about it.

The class matters more than the instance. Registering a bounded context takes entries in several independent lists, and each is a slice literal consumed elsewhere: omitting one breaks no build and fails no test. It just makes something quietly do less. Two of those lists were missed adding `rulecontent`, and review caught both rather than a gate. This is the third instance of the shape, already on main.

## What changes

`observability` is registered with the migrator, and two tests enumerate the contexts that ship migrations **from the tree** and assert each appears in the migrator's list and in the test fixture's.

Filesystem-driven rather than compared against a hardcoded expectation, which would be the same defect one level up: a context added without an entry would also be missing from the expectation, and the test would agree with the bug.

Both tests check the reverse direction too. A registered context whose migrations were renamed or removed applies nothing and reports success, so the CLI would again exit 0 having done less than it claims.

## Impact

- The migrator applies eight contexts rather than seven. Verified end to end against a fresh database: every context's tracking table is created, `observability`'s included.
- The canonical requirement named five contexts by hand, which had gone stale by three. That list is replaced with the property rather than an enumeration, so it cannot drift again.
