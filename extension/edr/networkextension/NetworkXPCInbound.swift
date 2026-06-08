/// XPC message-type strings exchanged between the Go agent and the network extension's XPCServer. The agent sends
/// `hello` on connect and on every heartbeat ping; the extension MUST reply with `hello-ack` or the agent's
/// `xpc_bridge_connect` handshake times out after 5s and tears the connection down (agent/xpcbridge/xpc_bridge.c,
/// issue #178). Kept distinct from the security extension's `XPCMessageType` because the two extensions are separate
/// Xcode targets / Swift modules with no shared framework (see extension/edr/Package.swift).
enum NetworkXPCMessageType {
    static let hello = "hello"
    static let helloAck = "hello-ack"
}

/// networkXPCShouldAck is the pure decision the network extension's XPCServer applies to an inbound message type: reply
/// with `hello-ack` only to a `hello`. The network extension has no other inbound control messages (unlike the security
/// extension's `application_control.update`), so every other type (including a missing type) is ignored.
///
/// Extracted as a free function so the extension-xpc-server hello-handshake contract is unit-testable without standing
/// up a real Mach listener; the Mach round-trip itself is validated at the system / VM layer per docs/testing-strategy.md.
/// Before this existed the network extension never answered the agent's hello, so its receiver timed out every reconnect
/// cycle and no network/DNS events were ever delivered.
func networkXPCShouldAck(type: String?) -> Bool {
    type == NetworkXPCMessageType.hello
}
