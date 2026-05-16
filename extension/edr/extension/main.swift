import Foundation
import EndpointSecurity

// Load the persisted application control snapshot BEFORE ESF starts subscribing.
// Startup order matters here — if we subscribed first, a racing exec of a blocked
// hash between subscribe and loadFromDisk would not yet see the snapshot. The
// Phase 3 decision engine plugs into ESFSubscriber's AUTH_EXEC handler; this
// step (Phase 2) wires the snapshot lifecycle so it's ready when Phase 3 lands.
ApplicationControlStore.shared.loadFromDisk()

let server = XPCServer(serviceName: "FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc")
server.start()

let subscriber = ESFSubscriber()
let serializer = EventSerializer()
subscriber.onEvent = { data in server.send(data: data) }
subscriber.start()

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
