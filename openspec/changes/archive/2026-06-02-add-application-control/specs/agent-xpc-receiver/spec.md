# Agent XPC Receiver Specification (delta)

## REMOVED Requirements

### Requirement: Outbound policy push routed to active connection

**Reason**: The blocklist push channel (the `policyDispatcher` lookup and the `Receiver.SendPolicy` Mach
message) is removed in phase 1 of the `add-application-control` change. Phase 4 of the same change
reintroduces the outbound channel for the typed `set_application_control` snapshot, at which point the
`extension-application-control` capability spec carries the contract for snapshot delivery.

**Migration**: None. The product has not shipped its first release; the legacy push channel is deleted in
the same change.
