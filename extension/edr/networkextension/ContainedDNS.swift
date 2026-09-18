import Foundation

/// ContainedDNS decides what the DNS proxy does with a query while the host is contained (#948): forward it only when it asks for the
/// EDR server's name, answer anything else locally with REFUSED, and drop what is not a query at all. The filter's lifeline has to allow
/// DNS for the agent to resolve the server, and every lookup on the host passes through this proxy, so restricting names here is what
/// keeps DNS from carrying traffic out of a contained host. Pure, so every decision is unit-testable.
enum ContainedDNS {
    enum Decision: Equatable {
        /// Forward the query upstream as usual.
        case forward
        /// Forward this query in place of the datagram: a contained host's allowed lookup rebuilt from its header, its question and,
        /// when the client offered one, an OPT record carrying a UDP payload size and nothing else. Everything else a process appends
        /// after the question (records, options or any other bytes) stays behind.
        case forwardQuestion(Data)
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
        /// RFC 1035 3.1: a name is at most 255 octets on the wire, its length octets and the root terminator included.
        static let maxNameLength = 255
        static let nscountOffset = 8
        static let arcountOffset = 10
        /// RFC 6891 6.1.2: an OPT record is a root name, type OPT (41), the requestor's UDP payload size in the CLASS field, a
        /// four-octet TTL holding the extended RCODE, the EDNS version and the flags, and then its option data. A minimal one, with no
        /// options, is these 11 octets.
        static let optRecordLength = 11
        static let optTypeHigh: UInt8 = 0x00
        static let optTypeLow: UInt8 = 0x29
        /// Offsets of an OPT record's fields, from its root name.
        static let optNameOffset = 0
        static let optTypeOffset = 1
        static let optUDPSizeOffset = 3
        static let optExtendedRCODEOffset = 5
        static let optVersionOffset = 6
        static let optFlagsOffset = 7
        static let optRDLengthOffset = 9
        static let lowByteMask: UInt16 = 0xFF
        /// The bounds a rebuilt query's UDP payload size is clamped to. 1232 is the size widely used as the largest that traverses the
        /// internet without IP fragmentation. 512 is the floor RFC 6891 6.2.3 puts under an advertised size, and is also what a client
        /// receives when it offers no OPT record at all, so raising an offer to it hands the client nothing it could not already take.
        static let maxAdvertisedUDPSize: UInt16 = 1232
        static let minAdvertisedUDPSize: UInt16 = 512
    }

    /// decision is the proxy's action for one UDP datagram. A host that is not contained forwards everything. A contained host forwards
    /// a single-question query whose name is one of the lifeline's names, compared case-insensitively and without a trailing dot, rebuilt
    /// from its header and question, and answers every other query REFUSED. A datagram that is not a well-formed query is dropped.
    static func decision(for datagram: Data, containment: NetworkContainmentUpdate?) -> Decision {
        guard let containment, containment.contained else { return .forward }
        guard let question = singleQuestion(in: datagram) else { return .drop }
        if let name = question.name, containment.serverNames.contains(name) {
            return .forwardQuestion(rebuilt(datagram, questionEnd: question.end))
        }
        return .answer(refused(datagram, questionEnd: question.end))
    }

    /// normalized is a name as the lifeline compares it: lowercase, without a trailing dot.
    static func normalized(_ name: String) -> String {
        let lower = name.lowercased()
        return lower.hasSuffix(".") ? String(lower.dropLast()) : lower
    }

    /// singleQuestion returns where the question of a one-question query ends, and its name normalized when every label is made of
    /// host-name characters. It returns nil for a response, a query with other than one question, or a question that runs past the
    /// datagram, uses a compression pointer or reserved label type, or spells a name over 255 octets, none of which a stub resolver
    /// sends. The name is read label by label rather than as text, so a label carrying a dot byte cannot spell the server's name.
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
                guard end <= bytes.count, offset + 1 - Wire.headerLength <= Wire.maxNameLength else { return nil }
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

    /// rebuilt builds the query that leaves the host: the client's ID, opcode, recursion-desired flag and question, every other flag
    /// clear, no records, and an OPT record when the client offered a usable one. What remains for a process to choose is the ID, the
    /// name and where the query goes; the rest of the datagram does not leave the host.
    ///
    /// The OPT record is this proxy's own, not the client's: a root name, type OPT, a UDP payload size, and nothing else. Without it an
    /// allowed answer over 512 octets comes back truncated and the stub retries over TCP, which is closed while contained, so a name
    /// with many addresses or one behind a CDN stops resolving (issue #1072). Rebuilding it rather than passing the client's through
    /// keeps the EDNS version, the DNSSEC-OK bit and any option out of what leaves the host; the platform's stub resolver does not
    /// validate DNSSEC, so clearing that bit costs an answer nothing here.
    private static func rebuilt(_ query: Data, questionEnd: Int) -> Data {
        let datagram = [UInt8](query)
        var bytes = [UInt8](query.prefix(questionEnd))
        bytes[Wire.flagsOffset] &= Wire.opcodeAndRD
        bytes[Wire.flagsOffset + 1] = 0
        for index in Wire.ancountOffset..<Wire.headerLength {
            bytes[index] = 0
        }
        guard let offered = offeredUDPSize(datagram, questionEnd: questionEnd) else { return Data(bytes) }
        // Clamped, not copied. The upper bound is what the client asked for, and then the cap, because the answer comes back to a stub
        // that sized its own buffer and a bigger one risks fragmentation. The lower bound raises an offer below 512 rather than
        // carrying it, since 512 is what a responder treats any smaller offer as and what the client would get with no record at all.
        let advertised = min(max(offered, Wire.minAdvertisedUDPSize), Wire.maxAdvertisedUDPSize)
        bytes[Wire.arcountOffset + 1] = 1
        bytes += [0, Wire.optTypeHigh, Wire.optTypeLow,
                  UInt8(advertised >> Wire.bitsPerByte), UInt8(advertised & Wire.lowByteMask),
                  0, 0, 0, 0, // extended RCODE, version, flags
                  0, 0] // no option data
        return Data(bytes)
    }

    /// offeredUDPSize is the UDP payload size the client advertised, and nil unless what follows the question is EXACTLY one minimal
    /// OPT record: the datagram ends there, the header counts one additional record and no others, the name is root, the type is OPT,
    /// the extended RCODE and version are zero, no flag is set, and there is no option data. Anything else, an option, a version this
    /// does not know, the DNSSEC-OK bit, a second record, or one byte too many, leaves the query rebuilt without an OPT, which is what
    /// it did before EDNS was carried at all.
    private static func offeredUDPSize(_ bytes: [UInt8], questionEnd: Int) -> UInt16? {
        func count(at offset: Int) -> UInt16 { UInt16(bytes[offset]) << Wire.bitsPerByte | UInt16(bytes[offset + 1]) }
        guard bytes.count == questionEnd + Wire.optRecordLength,
              count(at: Wire.ancountOffset) == 0, count(at: Wire.nscountOffset) == 0, count(at: Wire.arcountOffset) == 1,
              bytes[questionEnd + Wire.optNameOffset] == 0,
              bytes[questionEnd + Wire.optTypeOffset] == Wire.optTypeHigh,
              bytes[questionEnd + Wire.optTypeOffset + 1] == Wire.optTypeLow,
              bytes[questionEnd + Wire.optExtendedRCODEOffset] == 0,
              bytes[questionEnd + Wire.optVersionOffset] == 0,
              count(at: questionEnd + Wire.optFlagsOffset) == 0,
              count(at: questionEnd + Wire.optRDLengthOffset) == 0
        else { return nil }
        return count(at: questionEnd + Wire.optUDPSizeOffset)
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
