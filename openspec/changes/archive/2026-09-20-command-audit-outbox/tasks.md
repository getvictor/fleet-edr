# Tasks

- [x] Add `command.cancel` to the audit actions and pin its name.
- [x] Give the commands store a transaction runner and a transactional status update.
- [x] Add audited insert and status-update paths to the response service, committing the entry with the change.
- [x] Build the entry in the operator handler, with the action the route actually performed.
- [x] Cover an issuance and a withdrawal committing their entries, a refused action leaving none, and a recorder that is down for the action and back for the delivery.
