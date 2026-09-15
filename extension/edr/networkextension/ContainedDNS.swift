import Foundation

/// ContainedDNS decides what the DNS proxy does with a query while the host is contained (#948): forward it only when it asks for the
/// EDR server's name, answer anything else locally with REFUSED, and drop what is not a query at all. The filter's lifeline has to allow
/// DNS for the agent to resolve the server, and every lookup on the host passes through this proxy, so restricting names here is what
/// keeps DNS from carrying traffic out of a contained host. Pure, so every decision is unit-testable.
enum ContainedDNS {
    enum Decision: Equatable {
        /// Forward the query upstream as usual.
        case forward
        /// Forward the query, but only to one of the host's configured resolvers: a contained host's allowed lookup does not go to an
        /// address the client chose, which could be a server that reads what the query carries. The refused answer is for a host
        /// with no configured resolver.
        case forwardToSystemResolver(refused: Data)
        /// Answer the client with this response instead of forwarding.
        case answer(Data)
        /// Neither forward nor answer: the datagram is not a query this proxy can refuse.
        case drop
    }

    private enum Wire {
        static let headerLength = 12
        static let flagsOffset = 2
        static let qdcountOffset = 4
        static let qrBit: UInt8 = 0x80
        /// The opcode and RD bits of the first flags byte, copied from the query into the response.
        static let opcodeAndRD: UInt8 = 0x79
        /// RA set, RCODE 5 (REFUSED).
        static let refusedSecondFlags: UInt8 = 0x85
        static let questionTrailer = 4
        static let bitsPerByte: UInt16 = 8
        static let ancountOffset = 6
        static let maxLabelLength = 63
    }

    /// decision is the proxy's action for one UDP datagram. A host that is not contained forwards everything. A contained host forwards
    /// a single-question query whose name is one of the lifeline's names, compared case-insensitively and without a trailing dot, to a
    /// configured resolver, and answers every other query REFUSED. A datagram that is not a well-formed query is dropped.
    static func decision(for datagram: Data, containment: NetworkContainmentUpdate?) -> Decision {
        guard let containment, containment.contained else { return .forward }
        guard let question = singleQuestion(in: datagram) else { return .drop }
        let refusal = refused(datagram, questionEnd: question.end)
        if let name = question.name, containment.serverNames.contains(name) {
            return .forwardToSystemResolver(refused: refusal)
        }
        return .answer(refusal)
    }

    /// systemResolver is where a contained host's allowed lookup is sent: the resolver the client asked when it is one of the host's
    /// configured resolvers, otherwise the first configured one, and nil when there is none.
    static func systemResolver(for requested: String?, systemServers: [String]) -> String? {
        if let requested, systemServers.contains(where: { DNSUpstreamFailover.sameAddress($0, requested) }) {
            return requested
        }
        return systemServers.first
    }

    /// normalized is a name as the lifeline compares it: lowercase, without a trailing dot.
    static func normalized(_ name: String) -> String {
        let lower = name.lowercased()
        return lower.hasSuffix(".") ? String(lower.dropLast()) : lower
    }

    /// singleQuestion returns where the question of a one-question query ends, and its name normalized when every label is made of
    /// host-name characters. It returns nil for a response, a query with other than one question, or a question that runs past the
    /// datagram or uses a compression pointer or reserved label type, none of which a stub resolver sends. The name is read label by
    /// label rather than as text, so a label carrying a dot byte cannot spell the server's name.
    private static func singleQuestion(in data: Data) -> (end: Int, name: String?)? {
        let bytes = [UInt8](data)
        guard bytes.count >= Wire.headerLength, bytes[Wire.flagsOffset] & Wire.qrBit == 0,
              (UInt16(bytes[Wire.qdcountOffset]) << Wire.bitsPerByte | UInt16(bytes[Wire.qdcountOffset + 1])) == 1 else { return nil }
        var offset = Wire.headerLength
        var labels: [String] = []
        var plain = true
        while offset < bytes.count {
            let length = Int(bytes[offset])
            if length == 0 {
                let end = offset + 1 + Wire.questionTrailer
                guard end <= bytes.count else { return nil }
                return (end, plain && !labels.isEmpty ? normalized(labels.joined(separator: ".")) : nil)
            }
            // A length over 63 is a compression pointer or a reserved label type, neither of which a stub resolver sends.
            guard length <= Wire.maxLabelLength, offset + 1 + length <= bytes.count else { return nil }
            let label = bytes[(offset + 1)..<(offset + 1 + length)]
            if label.allSatisfy(isHostNameByte), let text = String(bytes: label, encoding: .ascii) {
                labels.append(text)
            } else {
                plain = false
            }
            offset += 1 + length
        }
        return nil
    }

    private static func isHostNameByte(_ byte: UInt8) -> Bool {
        (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z")) || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
            || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9")) || byte == UInt8(ascii: "-") || byte == UInt8(ascii: "_")
    }

    /// refused builds the REFUSED response to a query: its ID, its opcode and recursion-desired flag, and its question, with no records.
    private static func refused(_ query: Data, questionEnd: Int) -> Data {
        var bytes = [UInt8](query.prefix(questionEnd))
        bytes[Wire.flagsOffset] = Wire.qrBit | (bytes[Wire.flagsOffset] & Wire.opcodeAndRD)
        bytes[Wire.flagsOffset + 1] = Wire.refusedSecondFlags
        for index in Wire.ancountOffset..<Wire.headerLength {
            bytes[index] = 0
        }
        return Data(bytes)
    }
}
