import EndpointSecurity
import Foundation
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.securityextension", category: "ESFCredentialStores")

/// CredentialStoreSubscriber is a third, NOTIFY-only Endpoint Security client that reports when a program other than the browser
/// opens a browser's saved passwords or cookies (issue #1187). Infostealers read these files, and no other client reports a read:
/// the primary client does not subscribe to opens at all (ADR-0008), and the file-tamper client keeps only destructive ones.
///
/// It is a client of its own for the reason FileTamperSubscriber is: it inverts target-path muting so that ONLY the credential
/// files reach it, and inversion is client-global, so it cannot share a client whose other subscriptions need every path. It
/// subscribes to NOTIFY_OPEN alone, muted to the literal files CredentialStores.targets lists, and drops an open by the browser's
/// own team before anything is serialized, so a browser at work puts nothing on the wire.
///
/// Each reported open is an `open` event carrying the real access mode, which the server's file-write rules ignore, since they
/// read only opens that carry write access and change content.
final class CredentialStoreSubscriber: Sendable {
    // swiftlint:disable:next implicitly_unwrapped_optional
    private nonisolated(unsafe) var client: OpaquePointer!
    private let serializer = EventSerializer()
    nonisolated(unsafe) var onEvent: ((Data) -> Void)?

    /// queue serializes every change to the muted set, the start and each refresh. `applied` is only read and written on it.
    private let queue = DispatchQueue(label: "com.fleetdm.edr.credentialstores")
    /// applied is the literal paths currently muted, and so observed once inversion is on.
    private nonisolated(unsafe) var applied: [String] = []
    private nonisolated(unsafe) var refreshTimer: DispatchSourceTimer?
    /// refreshSeconds is how long a profile or an account added to the host goes unwatched at most. Listing the accounts and the
    /// browsers' profile directories is cheap, but both change rarely.
    private static let refreshSeconds = 300

    init() {
        var rawClient: OpaquePointer?
        let result = es_new_client(&rawClient) { [weak self] _, message in
            self?.handleOpen(message.pointee)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let rawClient else {
            // Not fatal, unlike the other clients: this one adds a detection, and the host's other telemetry must not go with it.
            logger.error("Failed to create credential-store ES client: \(result.rawValue)")
            return
        }
        self.client = rawClient
    }

    func start() {
        guard client != nil else {
            return
        }
        // The same order as the file-tamper client: clear the default mute set, mute the targets, THEN invert and subscribe, so there
        // is never a window in which every open on the host reaches this client.
        es_unmute_all_target_paths(client)
        queue.sync { refresh() }
        guard es_invert_muting(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) == ES_RETURN_SUCCESS else {
            logger.error("credential-store target-path mute inversion failed; the client stays unsubscribed")
            return
        }
        let events: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_OPEN]
        guard es_subscribe(client, events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            logger.error("credential-store subscribe failed")
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(Self.refreshSeconds), repeating: .seconds(Self.refreshSeconds))
        timer.setEventHandler { [weak self] in self?.refresh() }
        timer.resume()
        refreshTimer = timer
        logger.info("credential-store client active: \(self.appliedCount, privacy: .public) credential files watched")
    }

    private var appliedCount: Int {
        queue.sync { applied.count }
    }

    /// refresh mutes the credential files the homes and profiles hold now and unmutes the ones that are gone. Runs on queue.
    ///
    /// The same discipline as the file-tamper client's reconcile: mutes first, and unmutes only when every mute succeeded, so a
    /// partial update never drops watches before their replacements are in. A mute that fails is not recorded, so the next refresh
    /// tries it again. An account walk that fails keeps every file already watched, and a browser directory that could not be
    /// listed keeps the files already watched under it.
    private func refresh() {
        guard let homes = WatchedPaths.homeDirectories() else {
            logger.error("credential-store client could not read the accounts; keeping \(self.applied.count) watched files")
            return
        }
        let scanned = CredentialStores.targets(homes: homes, listDirectory: CredentialStores.listing)
        if !scanned.unreadableRoots.isEmpty {
            logger.error("credential-store client could not list \(scanned.unreadableRoots.count, privacy: .public) browser directories")
        }
        let next = CredentialStores.next(applied: applied, scanned: scanned)
        let appliedSet = Set(applied)
        let nextSet = Set(next)
        var failed = 0
        for path in next where !appliedSet.contains(path) {
            guard es_mute_path(client, path, ES_MUTE_PATH_TYPE_TARGET_LITERAL) == ES_RETURN_SUCCESS else {
                failed += 1
                continue
            }
            applied.append(path)
        }
        guard failed == 0 else {
            logger.error("credential-store client could not mute \(failed, privacy: .public) credential files; nothing unmuted")
            return
        }
        for path in applied where !nextSet.contains(path) {
            // Still muted, so still observed, when the unmute fails: it stays applied and the next refresh tries again.
            if es_unmute_path(client, path, ES_MUTE_PATH_TYPE_TARGET_LITERAL) == ES_RETURN_SUCCESS {
                applied.removeAll { $0 == path }
            }
        }
    }

    private func handleOpen(_ msg: es_message_t) {
        guard msg.event_type == ES_EVENT_TYPE_NOTIFY_OPEN else {
            return
        }
        let path = esTokenString(msg.event.open.file.pointee.path)
        let opener = msg.process.pointee
        guard !path.isEmpty, !CredentialStores.isOwnRead(path: path, openerTeamID: esTokenString(opener.team_id)) else {
            return
        }
        let pid = audit_token_to_pid(opener.audit_token)
        let payload = OpenPayload(pid: pid, path: path, flags: CredentialStores.openFlags(fflag: msg.event.open.fflag))
        if let data = serializer.serialize(eventType: "open", payload: payload, kernelTimeNs: kernelEventTimeNs(msg.time)) {
            logger.debug("credential-store open pid=\(pid, privacy: .public) path=\(path, privacy: .private)")
            onEvent?(data)
        }
    }

    func stop() {
        guard client != nil else {
            return
        }
        queue.sync { refreshTimer?.cancel() }
        es_unsubscribe_all(client)
        es_delete_client(client)
    }
}
