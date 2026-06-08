import Foundation
import EndpointSecurity
import os.log

// Load the persisted application control snapshot BEFORE ESF starts subscribing.
// Startup order matters here — if we subscribed first, a racing exec of a blocked
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
server.start()

let subscriber = ESFSubscriber()
let serializer = EventSerializer()
subscriber.onEvent = { data in server.send(data: data) }
subscriber.start()

// Dedicated, target-muted file-tamper client (#301, ADR-0008). It watches /etc/sudoers* for CREATE/WRITE via
// inverted target-path muting and lives on its own ES client — separate from `subscriber` above — so the client-global
// target-path inversion never filters the primary client's AUTH_EXEC (whose target is the executable). Its events flow into
// the same XPC pipeline; the server's sudoers_tamper rule consumes them as `open` (write-mode) events.
let fileTamper = FileTamperSubscriber()
fileTamper.onEvent = { data in server.send(data: data) }
fileTamper.start()

// Issue #11: ESF is a pure event stream — it only delivers events that occur
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
