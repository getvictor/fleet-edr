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
// doesn't hold up live ESF callback delivery, and so the wait-for-first-peer
// barrier below doesn't deadlock the main thread that drives dispatchMain().
//
// The waitForFirstPeer barrier guards against the post-restart race where
// the snapshot pass completes faster than the agent's XPC reconnect; without
// it, every baseline event is sent into an empty peer set and silently lost.
// 30s is generous — the agent reconnects within ~1s in practice but the
// extension can be activated standalone (no agent yet) during installer
// pre-bake; we'd rather wait the full 30s than fall through with the events
// dropped.
private let snapshotPeerWaitSeconds = 30
DispatchQueue.global(qos: .utility).async {
    let connected = server.waitForFirstPeer(timeout: .now() + .seconds(snapshotPeerWaitSeconds))
    if !connected {
        // Proceed anyway — at worst we lose the snapshot for this boot, which
        // is no worse than the pre-#11 behaviour. The next extension restart
        // (or agent install) gets another shot.
        return
    }
    ProcessSnapshotEnumerator.run { payload in
        guard let data = serializer.serialize(eventType: "exec", payload: payload) else { return }
        server.send(data: data)
    }
}

dispatchMain()
