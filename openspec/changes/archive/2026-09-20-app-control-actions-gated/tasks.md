# Tasks

- [x] Add the four application-control rule actions to the UI's action registry, named exactly as the server's chokepoint enforces them.
- [x] Gate each control on the permission its own call needs, sharing one permission across the three that PATCH.
- [x] Drop the Actions column and the "click Add rule" prompt for an operator who can change nothing.
- [x] Close an open dialog when the permission its submit needs is revoked, so the refresh reaches the whole page.
- [x] Cover every control both ways, and confirm an unknown permission set still renders optimistically.
