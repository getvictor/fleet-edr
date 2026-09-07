# Pin the dev XPC peer by identifier: tasks

## 1. Stable dev agent identifier

- [x] `Taskfile.yml` `build:agent`: after `go build`, re-sign the binary with `codesign --force --sign - --identifier fleet-edr-agent` as a `platforms: [darwin]` step so the ad-hoc agent carries a fixed identifier across rebuilds.

## 2. Debug peer requirement

- [x] `extension/edr/shared/XPCEventServer.swift`: replace `adHocCDHashDebug` with `agentIdentifierDebug = "fleet-edr-agent"`; change `debug` from an `or cdhash H"..."` clause to `or identifier "fleet-edr-agent"`; update the doc comments. Production requirement and the `#if DEBUG` selection are unchanged.

## 3. Spec

- [x] `extension-xpc-server` delta: MODIFIED "Peer code-signing validation" restates the requirement (adds the debug identifier-pin allowance) and replaces the debug scenario with the identifier-matching one.

## 4. Tests

- [x] `extension/edr/Tests/EDRExtensionLogicTests/XPCServerLogicTests.swift`: the debug test asserts the identifier clause is present and the cdhash clause is gone; the production test asserts the identifier-alone clause is absent. Marker updated to the renamed scenario, with a transitional second marker for the pre-rename canonical scenario (remove at archive).

## 5. Verification

- [ ] `openspec validate dev-xpc-peer-pin-by-identifier --strict`; spectrace; dash + markdown lints.
- [ ] Swift build + `EDRExtensionLogic` unit tests (`XPCServerLogicTests`) pass.
- [ ] `task build:agent` produces a binary whose `codesign -dvvv` identifier is `fleet-edr-agent`.

## 6. At archive (release checklist)

- [ ] Drop the transitional second `spec:` marker in `XPCServerLogicTests.swift` that points at the pre-rename canonical scenario `...code-directory-hash-matches-the-pinned-value`; the MODIFIED requirement replaces that scenario when this change is archived, so the marker would otherwise dangle.
