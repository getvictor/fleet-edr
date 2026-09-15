import Foundation
import Network
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "DNSProxy")

/// A contained host's DNS (#948). ContainedDNS decides each query; this bridges its decisions to the proxy's flows. In its own file so
/// DNSProxyProvider stays within SwiftLint's file-length cap.
extension DNSProxyProvider {
    /// answerLocally writes a locally built answer to the client, as if from the resolver it asked.
    static func answerLocally(_ answer: Data, to endpoint: Network.NWEndpoint, on flow: NEAppProxyUDPFlow) {
        flow.writeDatagrams([(answer, endpoint)]) { writeError in
            writeError.map { logger.error("Failed to write a contained host's refused answer: \($0.localizedDescription)") }
        }
    }

    /// closeIfContained closes a DNS over TCP session, with its upstream connection when it has one, and reports that it did, when the
    /// host is contained. DNS over TCP is not resolved while contained: a session is refused when it starts, and one opened before the
    /// host was contained is closed on its next query instead of carrying it.
    static func closeIfContained(_ flow: NEAppProxyTCPFlow, connection: Network.NWConnection?) -> Bool {
        guard NetworkContainmentController.shared.isContained else { return false }
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        connection?.cancel()
        return true
    }
}
