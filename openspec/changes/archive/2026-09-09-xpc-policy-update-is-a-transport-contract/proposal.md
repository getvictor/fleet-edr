# Narrow the inbound policy-update requirement to the transport it owns

## Why

`extension-xpc-server/Inbound policy update` describes the XPC message that delivers an application-control snapshot to the system extension. The transport half is accurate and live. Everything it says about what happens next is not:

- it calls the payload a "blocklist", which the model stopped being when application control moved to a typed rule snapshot;
- its scenario says the agent sends a `policy.update` message, a type the extension does not accept;
- it says the extension "MUST replace the active blocklist" and "MUST persist that policy", which is a shorter, older restatement of behaviour `extension-application-control/Snapshot is the source of truth for decisions` now specifies in full, including a recency gate on `policy_version` and `policy_epoch` that this requirement does not mention at all.

That is the failure mode the #905 audit keeps finding: two requirements describing one behaviour, one of them frozen. The fix is to make this requirement own the transport and defer the rest, rather than to delete it. The transport is genuinely this capability's concern, and it carries a safety property nothing else states: a malformed push must not disarm enforcement.

## What changes

- Rewrite the requirement to the message contract: accept `application_control.update` from a validated peer, hand the `data` bytes to the snapshot store unread, and reject an absent or empty `data` without touching the active snapshot or closing the connection.
- Rename the scenario `The agent pushes a new blocklist` to `The agent pushes a new snapshot` and correct its body, which named a message type that does not exist.
- Move the marker on the covering test, and rewrite that test's comment, which repeated the "cross-restart persistence the spec requires" claim this requirement no longer makes.

## What is deliberately NOT changed

`agent-xpc-receiver/Outbound policy push routed to active connection` is reported by `archive-verify` as a retirement the archive did not apply, and I was about to remove it as dead. It is not dead.

The archived change retired the *legacy* channel (`policyDispatcher`, `Receiver.SendPolicy`) and said in its own removal note that a later phase would reintroduce an outbound channel for the typed snapshot. That is what happened: `receiver.Dispatcher.SendApplicationControl` sends over the active connection and returns `ErrNoConnector` when none is published, which is exactly what the requirement states, and `agent/receiver/loop_test.go` covers both scenarios today. Searching for the old symbol names finds nothing and reads like a deletion; the successor is the same contract under new names.

It is recorded in `openspec/archive-verify-exceptions.yaml` instead, so the finding stops reporting as an unrepaired drop.

## Impact

- Affected specs: `extension-xpc-server`
- Affected code: `extension/edr/Tests/EDRExtensionLogicTests/XPCServerLogicTests.swift` (marker and comment only)
- No behaviour changes. The extension already does exactly what the rewritten requirement says.
