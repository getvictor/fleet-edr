import Foundation

/// DisabledProviderStore remembers which capture providers an operator switched off, across extension restarts (issue #1078).
///
/// The liveness report is rebuilt from scratch by each extension process, and a provider that is disabled never starts and therefore
/// never stops, so no callback tells a fresh process that it was switched off. Without this, `disabled` survives only until the next
/// restart and a rebooted host is back to reporting nothing, which is the state the issue reported in the first place.
///
/// Why this and not the configuration itself: `NEDNSProxyManager` answers inside the HOST APP, which is the context that wrote the
/// configuration, and not inside this extension. Measured on a live host, `loadFromPreferences` here reports `isEnabled=false` in the
/// same process, at the same second, as the log line saying the DNS proxy started. Reading it would therefore claim every host had the
/// proxy switched off, which is worse than saying nothing. The system's own store is a keyed archive whose shape is undocumented, so
/// parsing it would fail in the same direction on the first release that changed it.
///
/// What this cannot cover, stated rather than hidden: a provider that was already disabled before this version first ran, and has not
/// been toggled since, was never observed stopping, so there is nothing to have remembered. That host reports the provider absent, as
/// it did before, which a reader already treats as "unreported" rather than as "capturing".
final class DisabledProviderStore {
    /// defaultStoragePath sits beside the containment state and the application-control snapshot.
    static let defaultStoragePath = "/var/db/com.fleetdm.edr/disabled-providers.json"

    private let storagePath: String

    init(storagePath: String = DisabledProviderStore.defaultStoragePath) {
        self.storagePath = storagePath
    }

    /// load returns the providers last recorded as switched off. An unreadable or corrupt file yields none: a provider wrongly thought
    /// disabled is corrected within seconds by the start callback, and one wrongly thought running would be a false positive claim,
    /// so the direction to fail in is "remember nothing".
    func load() -> Set<String> {
        guard let data = FileManager.default.contents(atPath: storagePath),
              let names = try? JSONDecoder().decode([String].self, from: data) else {
            return []
        }
        return Set(names)
    }

    /// save records the set, and reports whether it was written. A failure is the caller's to log: the in-memory state is still
    /// correct for this process's lifetime, so the cost is confined to what a later restart remembers.
    @discardableResult
    func save(_ providers: Set<String>) -> Bool {
        guard let data = try? JSONEncoder().encode(providers.sorted()) else { return false }
        return (try? AtomicFile.write(data, toPath: storagePath)) != nil
    }
}
