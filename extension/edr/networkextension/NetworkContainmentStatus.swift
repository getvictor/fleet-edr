import Foundation

/// NetworkContainmentStatus is what the extension reports about containment: the update it holds and whether the content filter
/// applied it. The agent reports it on, so the console can tell a host that has been told to contain from one that is contained.
struct NetworkContainmentStatus: Codable, Equatable, Sendable {
    let contained: Bool
    let version: Int64
    let epoch: Int64
    let applied: Bool
    let error: String?
    /// appliedAddresses are the server addresses of the lifeline the running filter was confirmed to enforce, and nil when none was.
    ///
    /// Here because a lifeline refresh sends the same version and epoch with different addresses, so without it two different
    /// lifelines report an identical status and the agent cannot tell which one the filter holds (issue #1066). The agent pins its
    /// dials to the addresses named here, so it never dials an address the filter is not yet allowing.
    let appliedAddresses: [String]?
    /// appliedReachableVersion is the reachable-address set the running filter was confirmed to enforce, and nil when none was.
    ///
    /// Here for the same reason the addresses are, and for a sharper one: a change to that set reuses the containment version and
    /// epoch, so without it a status describing the PREVIOUS set is indistinguishable from one describing the new one, and an agent
    /// waiting for a set change to be applied would accept the older status as its confirmation and report success (issue #1059).
    let appliedReachableVersion: Int64?

    init(contained: Bool, version: Int64, epoch: Int64, applied: Bool, error: String?, appliedAddresses: [String]?,
         appliedReachableVersion: Int64? = nil) {
        self.contained = contained
        self.version = version
        self.epoch = epoch
        self.applied = applied
        self.error = error
        self.appliedAddresses = appliedAddresses
        self.appliedReachableVersion = appliedReachableVersion
    }

    /// eventType is the control event type the agent filters on, as it does for provider status.
    static let eventType = "ne_containment_status"
}
