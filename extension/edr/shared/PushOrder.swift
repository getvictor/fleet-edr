import Foundation

/// PushOrder is how the extensions order a document the server pushes: by epoch, the server's update time for it in Unix microseconds,
/// then by version. The server forces each update time past the one in its database, so epoch orders every document that database
/// issues, and after a restore sends version backwards the next document is ahead once the database clock is past any epoch the
/// restore lost. Version breaks a tie, which is what orders documents from a server that sends no epoch.
///
/// One definition for the application-control snapshot, the watched-path set and the network containment state, so the three cannot
/// drift apart on what "newer" means.
struct PushOrder: Comparable, Sendable {
    let epoch: Int64
    let version: Int64

    static func < (lhs: PushOrder, rhs: PushOrder) -> Bool {
        (lhs.epoch, lhs.version) < (rhs.epoch, rhs.version)
    }
}
