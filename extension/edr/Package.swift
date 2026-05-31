// swift-tools-version:5.9
//
// SwiftPM facade over the same Swift sources the Xcode `edr` project builds, so the pure-logic
// classes can be exercised by XCTest without a full ESF/NetworkExtension host. `swift test` runs
// in CI on every PR that touches extension/**.
//
// The Xcode project (edr.xcodeproj, sibling to this manifest) remains the production build path
// for the signed system extension + network extension + host app bundles. This package only
// references files that have no ESF / NetworkExtension framework dependencies; main.swift,
// XPCServer, ESFClient and friends are deliberately NOT in the source list. Adding a file here
// without considering its framework dependencies will trip the `swift build` invocation and
// surface in CI as a red gate.
//
// Why not a test target inside edr.xcodeproj: the project deliberately has no shared framework
// target (each binary slice carries its own entitlements), so adding an XCTest bundle would
// require pbxproj surgery to wire test-host + framework search paths against the existing
// targets. SwiftPM is the lighter touch: one Package.swift, one directory for tests, no manual
// project-file edits.

import PackageDescription

let package = Package(
    name: "EDRExtensionLogic",
    platforms: [.macOS(.v13)],
    products: [
        .library(
            name: "EDRExtensionLogic",
            targets: ["EDRExtensionLogic"]
        )
    ],
    targets: [
        // Files explicitly listed via `sources:` so SwiftPM does NOT auto-walk extension/ or
        // networkextension/ and pull in main.swift, ESFClient.swift, networkextension/XPCServer.swift,
        // etc. -- those import EndpointSecurity / NetworkExtension which only link inside their
        // respective Xcode targets. The system extension's XPCServer.swift IS in the source list
        // (it only depends on Foundation + libxpc, both available to SwiftPM) so the
        // extension-xpc-server unit tests can drive it. Adding a new pure-logic file is a one-line
        // edit here.
        .target(
            name: "EDRExtensionLogic",
            // `exclude:` silences the SwiftPM "unhandled file" warning by telling the build
            // graph that the Xcode project tree (host app, entitlements, Info.plist, build
            // artifacts) is intentionally not part of this package. The explicit `sources:`
            // list still defines what compiles -- exclude only suppresses scan noise.
            path: ".",
            exclude: [
                "build",
                "tmp",
                "edr.xcodeproj",
                "Tests",
                // The host-app target's executable-and-AppKit files. main.swift has top-level executable
                // code (legal only in an entry-point file, illegal in a library target); BlockAlert /
                // NotificationListener / BlockNotification pull in AppKit-only UI surfaces (NSAlert,
                // NSApplication) that belong in the production host-app bundle, not in the EDRExtensionLogic
                // library whose role is to expose pure-logic types for XCTest. SwiftPM CAN link AppKit on a
                // .macOS target — the exclusion is library-hygiene (no UI deps, no top-level code), not a
                // SwiftPM linker limitation. edr/ExtensionManagerLogic.swift IS in the source list below
                // (pure-logic types only, no top-level code) so host-app-extension-manager spec scenarios
                // are unit-testable.
                "edr/main.swift",
                "edr/BlockAlert.swift",
                "edr/NotificationListener.swift",
                "edr/BlockNotification.swift",
                "edr/Info.plist",
                "edr/edr.entitlements",
                "extension/Info.plist",
                "extension/extension.entitlements",
                "extension/main.swift",
                "extension/ESFStringToken.swift",
                "extension/ESFSubscriber.swift",
                // ESFSubscriber's handler splits (+FileEvents / +BTM / +AuthExec) and the cdhash helpers depend on
                // EndpointSecurity es_* types, so they belong to the Xcode extension target, not this pure-logic library.
                // Listed here to keep `swift build` free of the "unhandled file" warning (the explicit sources list below
                // still defines what actually compiles).
                "extension/ESFSubscriber+FileEvents.swift",
                "extension/ESFSubscriber+BTM.swift",
                "extension/ESFSubscriber+AuthExec.swift",
                "extension/CDHashHex.swift",
                "extension/NotificationClient.swift",
                "extension/ProcessSnapshotEnumerator.swift",
                "networkextension/Info.plist",
                "networkextension/networkextension.entitlements",
                "networkextension/main.swift",
                "networkextension/DNSProxyProvider.swift",
                "networkextension/NetworkEventSerializer.swift",
                "networkextension/NetworkFilter.swift",
                "networkextension/ProcessInfo.swift",
                "networkextension/XPCServer.swift",
                "com.fleetdm.edr.notify.plist"
            ],
            sources: [
                "edr/ExtensionManagerLogic.swift",
                "extension/ApplicationControlStore.swift",
                "extension/AuthExecDecider.swift",
                "extension/XPCServer.swift",
                "extension/BlockNotification.swift",
                "extension/EventSerializer.swift",
                "extension/FileHashCache.swift",
                "extension/SigningInfoFallback.swift",
                "networkextension/DNSParser.swift"
            ]
        ),
        .testTarget(
            name: "EDRExtensionLogicTests",
            dependencies: ["EDRExtensionLogic"],
            path: "Tests/EDRExtensionLogicTests"
        )
    ]
)
