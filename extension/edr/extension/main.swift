import Foundation
import EndpointSecurity
import os.log

// Load the persisted application control snapshot BEFORE ESF starts subscribing.
// Startup order matters here: if we subscribed first, a racing exec of a blocked
// hash between subscribe and loadFromDisk would not yet see the snapshot. The
// decision engine plugs into ESFSubscriber's AUTH_EXEC handler and consults
// this snapshot on every exec.
ApplicationControlStore.shared.loadFromDisk()

// Dedicated, target-muted file-tamper client (#301, ADR-0008). It watches the built-in sudoers paths plus the set the server last
// pushed (#998) via inverted target-path muting, and lives on its own ES client (separate from `subscriber` below) so the
// client-global target-path inversion never filters the primary client's AUTH_EXEC (whose target is the executable). Constructed
// here, ahead of the XPC server, because the server's inbound hook applies pushed sets to it; it starts subscribing further down.
// It starts from the persisted set so a restarted extension watches the operator's paths from its first event.
let watchedPathStore = WatchedPathStore()
let fileTamper = FileTamperSubscriber(pushed: watchedPathStore.current?.paths ?? [])
let watchedPathsLogger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "WatchedPaths")

// The security extension wires the shared XPCEventServer's inbound hooks to apply app-control policy and watched-path sets pushed
// by the agent.
let server = XPCEventServer(
    serviceName: "FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc",
    logger: Logger(subsystem: "com.fleetdm.edr.securityextension", category: "XPCServer"),
    onApplicationControl: { data in ApplicationControlStore.shared.apply(rawJSON: data) },
    onWatchedPaths: { data in
        // The store turns away a payload that is not a watched-path document and a set older than the one in force, which commands
        // delivered out of order would otherwise put back; either way the active and persisted sets stay as they were.
        guard let update = watchedPathStore.accept(data) else {
            let current = watchedPathStore.current
            // The store logs a persist failure itself; this line covers every refusal, so it names none of them.
            let skip = "watched_paths.update not accepted; the set in force is " +
                "version=\(current?.version ?? 0) epoch=\(current?.epoch ?? 0)"
            watchedPathsLogger.info("\(skip, privacy: .public)")
            return
        }
        let summary = "watched_paths.update version=\(update.version) epoch=\(update.epoch) " +
            "paths=\(update.paths.count) skipped=\(update.skipped)"
        watchedPathsLogger.info("\(summary, privacy: .public)")
        fileTamper.apply(pushed: update.paths)
    }
)
// Per-producer EventSerializer instances. EventSerializer wraps a JSONEncoder that must not be shared across concurrent
// producers, so each independent emit path owns one (matching ESFSubscriber / FileTamperSubscriber, which each construct their
// own): `serializer` drives the background process-snapshot enumerator below; `resyncSerializer` drives the resync path.
let serializer = EventSerializer()
let resyncSerializer = EventSerializer()

// Wire the re-sync reporter BEFORE server.start(): the XPC listener can deliver an application_control.update the instant it
// opens, and apply() invokes this reporter on the regression path. Installing it first closes the startup window where an
// early regression push would be applied (and logged) with no reporter attached, silently dropping the
// application_control_resync event. The reporter surfaces a snapshot accepted despite a regressed policy_version (because its
// epoch advanced, the server-DB-restore signature) so the regression is operator-visible, not just a host log line. (#322)
ApplicationControlStore.shared.resyncReporter = { payload in
    guard let data = resyncSerializer.serialize(eventType: "application_control_resync", payload: payload) else { return }
    server.send(data: data)
}

server.start()

let subscriber = ESFSubscriber()
subscriber.onEvent = { data in server.send(data: data) }
subscriber.start()

// The file-tamper client's events flow into the same XPC pipeline; the server's sudoers_tamper rule consumes them as `open`
// (write-mode) events.
fileTamper.onEvent = { data in server.send(data: data) }
fileTamper.start()

// Issue #11: ESF is a pure event stream that only delivers events occurring
// after es_subscribe. Anything already running (Safari, Slack, Finder, user
// LaunchAgents, every long-lived daemon) is invisible to the tree until it
// exec's again. Walk the process table via sysctl(KERN_PROC_ALL) and emit a
// synthetic exec event per live PID so the server materialises a baseline
// tree. Dispatched onto a background queue so the per-PID proc_pidpath cost
// doesn't hold up live ESF callback delivery.
//
// No explicit wait-for-peer barrier is needed: XPCServer buffers sends when
// no peer is connected and flushes the buffer to the first surviving peer
// (issue #173 QA discovered a phantom XPC peer that connects+disconnects in
// ~10ms after extension restart; the buffer makes us robust to that race).
DispatchQueue.global(qos: .utility).async {
    ProcessSnapshotEnumerator.run { payload in
        guard let data = serializer.serialize(eventType: "exec", payload: payload) else { return }
        server.send(data: data)
    }
}

dispatchMain()
