# Tasks

- [x] Read the pinned process by id when the window read did not cover it.
- [x] Walk its ancestors with the store's existing generation-resolving lookup, rather than a second ordering.
- [x] Leave the page's counts describing the page.
- [x] Bound the walk so a cycle in ppid cannot spin.
- [x] Test against a page that provably cannot hold the chain, with the unpinned read as the control.
