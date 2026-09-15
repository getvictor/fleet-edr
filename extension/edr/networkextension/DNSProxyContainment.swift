import Foundation
import Network
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.fleetdm.edr.networkextension", category: "DNSProxy")

/// A contained host's DNS (#948). ContainedDNS decides each query; this bridges its decisions to the proxy's flows. In its own file so
/// DNSProxyProvider stays within SwiftLint's file-length cap.
extension DNSProxyProvider {
    /// forwardContainedDatagram sends a contained host's allowed lookup to a configured resolver, never to an address the client chose:
    /// request's target is replaced with a configured resolver unless it already is one, and the answer still comes back as if from
    /// the resolver the client asked. With no configured resolver the lookup is refused.
    func forwardContainedDatagram(_ request: UDPForwardRequest, refused: Data) {
        let requested = DNSUpstreamFailover.address(of: request.target)
        guard let server = ContainedDNS.systemResolver(for: requested, systemServers: resolvers.addresses()) else {
            Self.answerLocally(refused, to: request.replyEndpoint, on: request.flow)
            return
        }
        guard server != requested else {
            forwardUDPDatagram(request)
            return
        }
        forwardUDPDatagram(UDPForwardRequest(datagram: request.datagram, target: .hostPort(host: .init(server), port: DNSProxy.dnsPort),
                                             replyEndpoint: request.replyEndpoint, flow: request.flow, ctx: request.ctx,
                                             route: request.route, isFailover: false))
    }

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
