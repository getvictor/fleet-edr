import Foundation
import os
import Security

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "ProviderLookup")

/// NetworkExtensionProviderLookup answers one question on the DNS hot path: does the process that opened this flow hold
/// `com.apple.developer.networking.networkextension`, i.e. is it itself a network-extension provider?
///
/// That is the honest, vendor-agnostic definition of "another resolver we must not sit in front of" (issue #656). Matching
/// on a bundle-ID allowlist would silently fail for every VPN the list does not name, and the incident host had four VPN
/// configurations installed; matching on the executable's bundle shape (`.appex` / `.systemextension`) would also decline
/// ordinary app extensions doing ordinary lookups, costing telemetry for no safety gain.
///
/// Cost and caching follow `SigningInfoFallback` in the security extension: SecCode walks the signing block, which is a few
/// hundred microseconds, so the result is memoised. The key is `(pid, pidversion)`, the kernel PID generation, which is the
/// same identity the flow telemetry already uses to stay immune to PID reuse (issue #403): a recycled PID is a different
/// generation and therefore a cache miss, so a short-lived process cannot inherit a previous tenant's verdict. The cache is
/// bounded and purged wholesale when full, because DNS flow rates make an LRU's bookkeeping more expensive than the
/// occasional cold walk, and a cold miss is self-healing.
///
/// Concurrency: `handleNewFlow` is called concurrently, so the cache is guarded by an unfair lock around a constant-time
/// dictionary lookup, the same shape `SigningInfoFallback` and `ApplicationControlStore` use.
final class NetworkExtensionProviderLookup {
    static let shared = NetworkExtensionProviderLookup()

    /// The entitlement that defines a network-extension provider.
    private static let networkExtensionEntitlement = "com.apple.developer.networking.networkextension"

    /// Cap on memoised verdicts. Each entry is a key plus a Bool, so a few thousand is negligible memory, and it bounds the
    /// growth a churn of short-lived resolver processes could otherwise cause.
    private static let maxCachedVerdicts = 4096

    /// Identifies one process generation. Pid alone is not enough: pids recycle, and a recycled pid belonging to a
    /// different program must not read a cached verdict that was computed for its predecessor.
    private struct Key: Hashable {
        let pid: pid_t
        let pidversion: UInt32
    }

    private let lock = OSAllocatedUnfairLock<[Key: Bool]>(initialState: [:])

    /// isProvider reports whether the process identified by `auditToken` holds the network-extension entitlement.
    ///
    /// Returns false when the token is absent or the process cannot be resolved. That is the deliberate fail-open choice
    /// for THIS rule: an unresolvable source means we cannot prove it is another provider, and declining every flow we
    /// cannot attribute would blind the monitoring tap far more often than it would prevent a deadlock. The flows the
    /// 2026-07-27 incident could not attribute (Tailscale's MagicDNS netstack flows, which arrive with no usable source
    /// process) are therefore NOT caught by this rule; they are tracked separately.
    func isProvider(auditToken: Data?, identity: ProcessIdentity) -> Bool {
        guard let auditToken, identity.pid > 0, let pidversion = identity.pidversion else { return false }
        let key = Key(pid: identity.pid, pidversion: pidversion)

        if let cached = lock.withLock({ $0[key] }) { return cached }

        let verdict = readEntitlement(auditToken: auditToken)
        lock.withLock { cache in
            // Purge wholesale rather than evicting one entry: see the type comment on why LRU bookkeeping is not worth it
            // at DNS flow rates.
            if cache.count >= Self.maxCachedVerdicts { cache.removeAll(keepingCapacity: true) }
            cache[key] = verdict
        }
        return verdict
    }

    /// readEntitlement performs the SecCode walk for one process. Separated from the caching so the cost is obvious at the
    /// call site and so a failure returns the same fail-open false the cache stores.
    private func readEntitlement(auditToken: Data) -> Bool {
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit: auditToken] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else {
            return false
        }

        var information: CFDictionary?
        // SecCode is a subtype of SecStaticCode in the Security type hierarchy; the signing-information call is declared
        // against the static type and accepts a dynamic code reference. kSecCSDynamicInformation asks about the running
        // process rather than the on-disk image, and kSecCSRequirementInformation is what populates the entitlements dict.
        let flags = SecCSFlags(rawValue: kSecCSDynamicInformation | kSecCSRequirementInformation)
        let status = SecCodeCopySigningInformation(unsafeBitCast(code, to: SecStaticCode.self), flags, &information)
        guard status == errSecSuccess,
              let info = information as? [String: Any],
              let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] else {
            return false
        }
        return entitlements[Self.networkExtensionEntitlement] != nil
    }
}
