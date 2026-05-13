# Extension XPC Server Specification (delta)

## REMOVED Requirements

### Requirement: Inbound policy update

**Reason**: The `policy.update` XPC message type and its `PolicyStore.apply(rawJSON:)` callback are removed
in phase 1 of the `add-application-control` change. The typed snapshot delivery channel reintroduces an
inbound message type in phase 4 of the same change; the snapshot acceptance contract is covered by the
`extension-application-control` capability spec rather than this one.

**Migration**: None. The product has not shipped its first release; the legacy message type is deleted in
the same change.
