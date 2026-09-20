# Tasks

- [x] Order application-control snapshots and watched-path sets by epoch, then version, in the extension.
- [x] Force the application-control policy epoch past its previous value on every mutation, in the server and the demo seeder.
- [x] Unit tests for both orderings and an integration test that the policy epoch advances when the database clock steps back; mutation-check them.
- [x] Verify on a VM that a pre-restore snapshot and set are refused and post-restore ones re-sync.
