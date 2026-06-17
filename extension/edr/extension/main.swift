import Foundation
import EndpointSecurity
import os.log

// Load the persisted application control snapshot BEFORE ESF starts subscribing.
// Startup order matters here: if we subscribed first, a racing exec of a blocked
// hash between subscribe and loadFromDisk would not yet see the snapshot. The
// decision engine plugs into ESFSubscriber's AUTH_EXEC handler and consults
// this snapshot on every exec.
ApplicationControlStore.shared.loadFromDisk()

// The security extension wires the shared XPCEventServer's inbound hook to apply app-control policy pushed by the agent.
let server = XPCEventServer(
    serviceName: "FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc",
    logger: Logger(subsystem: "com.fleetdm.edr.securityextension", category: "XPCServer"),
    onApplicationControl: { data in ApplicationControlStore.shared.apply(rawJSON: data) }
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

// Dedicated, target-muted file-tamper client (#301, ADR-0008). It watches /etc/sudoers* for CREATE/WRITE via
// inverted target-path muting and lives on its own ES client (separate from `subscriber` above) so the client-global
// target-path inversion never filters the primary client's AUTH_EXEC (whose target is the executable). Its events flow into
// the same XPC pipeline; the server's sudoers_tamper rule consumes them as `open` (write-mode) events.
let fileTamper = FileTamperSubscriber()
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
