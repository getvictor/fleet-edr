# Server Admin Surface Specification (delta)

## REMOVED Requirements

### Requirement: Read the current blocklist policy

**Reason**: Replaced by the typed Application Control REST surface (`GET /api/v1/app-control/policies`,
`/policies/{id}`, `/rules`) introduced in the `server-application-control` capability spec. The singleton
blocklist exposed at `GET /api/policy` cannot represent named policies, per-rule lifecycle metadata, or
host-group scoping.

**Migration**: None. The product has not shipped its first release; the legacy endpoint is deleted in the
same change.

### Requirement: Persist and fan out a new blocklist policy

**Reason**: Replaced by the typed Application Control REST surface (`POST` / `PATCH` / `DELETE` under
`/api/v1/app-control/policies` and `/policies/{id}/rules`, plus the per-policy `set_application_control`
fan-out in the `server-application-control` capability spec). The singleton `PUT /api/policy` flow cannot
represent named policies, per-rule lifecycle metadata, or host-group scoping.

**Migration**: None. The product has not shipped its first release; the legacy endpoint is deleted in the
same change.
