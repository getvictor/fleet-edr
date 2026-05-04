import Foundation

/// Minimal RFC 1035 DNS packet parser for extracting query name, type, and response addresses.
/// All parsing is best-effort -- malformed packets return nil/empty rather than crashing.
enum DNSParser {
    /// RFC 1035 + RFC 3596 wire-format constants. Names follow the field names in the RFCs
    /// so the parser reads next to the spec without an extra translation layer.
    private enum Wire {
        /// Fixed DNS header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2).
        static let headerLength = 12
        /// Byte offset of QDCOUNT (high byte) inside the header.
        static let qdcountOffset = 4
        /// Byte offset of ANCOUNT (high byte) inside the header.
        static let ancountOffset = 6
        /// Bytes that follow each question's QNAME: QTYPE(2) + QCLASS(2).
        static let questionTrailer = 4
        /// Resource-record fixed prefix after the NAME field:
        /// TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
        static let rrPrefixLength = 10
        /// Byte offset of RDLENGTH (high byte) within the resource-record prefix.
        static let rdlengthOffset = 8
        /// Top two bits set in a length byte signal a compression pointer (§4.1.4).
        static let compressionPointerMarker: UInt8 = 0xC0
        /// A compression pointer is two bytes total.
        static let compressionPointerLength = 2
        /// Resource-record TYPE codes we extract addresses from.
        static let typeA: UInt16 = 1
        static let typeAAAA: UInt16 = 28
        /// IPv4 / IPv6 RDATA widths.
        static let ipv4Length = 4
        static let ipv6Length = 16
        /// IPv6 is rendered as eight UInt16 groups separated by colons.
        static let ipv6GroupStride = 2
        /// Bits per byte. Used to combine two big-endian bytes into a UInt16.
        static let bitsPerByte = 8
    }

    /// Extracts the first query name from a DNS packet.
    static func queryName(from data: Data) -> String? {
        guard data.count > Wire.headerLength else { return nil }
        let qdcount = readUInt16(data, at: Wire.qdcountOffset)
        guard qdcount > 0 else { return nil }

        var offset = Wire.headerLength
        var labels: [String] = []

        while offset < data.count {
            let length = Int(data[offset])
            offset += 1

            if length == 0 { break } // end of name
            if length >= Wire.compressionPointerMarker { return nil } // pointer -- we don't resolve it
            guard offset + length <= data.count else { return nil }

            let label = String(data: data[offset..<offset + length], encoding: .utf8) ?? ""
            labels.append(label)
            offset += length
        }

        return labels.isEmpty ? nil : labels.joined(separator: ".")
    }

    /// Extracts the query type string from a DNS packet.
    static func queryType(from data: Data) -> String {
        guard data.count > Wire.headerLength else { return "unknown" }
        var offset = Wire.headerLength
        while offset < data.count {
            let length = Int(data[offset])
            offset += 1
            if length == 0 { break }
            if length >= Wire.compressionPointerMarker {
                offset += 1 // pointer is two bytes total; consume the trailing byte
                break
            }
            offset += length
        }

        // QTYPE is 2 bytes after QNAME
        guard offset + MemoryLayout<UInt16>.size <= data.count else { return "unknown" }
        let qtype = readUInt16(data, at: offset)
        return qtypeToString(qtype)
    }

    /// Extracts A and AAAA record addresses from a DNS response packet.
    static func responseAddresses(from data: Data) -> [String] {
        guard data.count > Wire.headerLength else { return [] }

        let ancount = readUInt16(data, at: Wire.ancountOffset)
        guard ancount > 0 else { return [] }

        let qdcount = readUInt16(data, at: Wire.qdcountOffset)
        guard let questionsEnd = skipQuestions(in: data, count: qdcount, startOffset: Wire.headerLength) else {
            return []
        }

        var offset = questionsEnd
        var addresses: [String] = []
        for _ in 0..<ancount {
            guard let (addr, newOffset) = parseAnswer(in: data, at: offset) else { break }
            if let addr { addresses.append(addr) }
            offset = newOffset
        }
        return addresses
    }

    /// Skips the question section of a DNS packet. Returns the new offset or nil on error.
    private static func skipQuestions(in data: Data, count: UInt16, startOffset: Int) -> Int? {
        var offset = startOffset
        for _ in 0..<count {
            offset = skipName(in: data, at: offset)
            offset += Wire.questionTrailer
            guard offset <= data.count else { return nil }
        }
        return offset
    }

    /// Parses a single answer record. Returns the address (if A/AAAA) and the new offset.
    private static func parseAnswer(in data: Data, at start: Int) -> (String?, Int)? {
        guard start < data.count else { return nil }
        let afterName = skipName(in: data, at: start)
        guard afterName + Wire.rrPrefixLength <= data.count else { return nil }

        let rrType = readUInt16(data, at: afterName)
        let rdlength = Int(readUInt16(data, at: afterName + Wire.rdlengthOffset))
        let rdataStart = afterName + Wire.rrPrefixLength
        guard rdataStart + rdlength <= data.count else { return nil }

        let address = parseRecordData(in: data, type: rrType, start: rdataStart, length: rdlength)
        return (address, rdataStart + rdlength)
    }

    private static func parseRecordData(in data: Data, type rrType: UInt16, start: Int, length: Int) -> String? {
        if rrType == Wire.typeA && length == Wire.ipv4Length {
            return formatIPv4(data, start: start)
        }
        if rrType == Wire.typeAAAA && length == Wire.ipv6Length {
            return formatIPv6(data, start: start)
        }
        return nil
    }

    private static func formatIPv4(_ data: Data, start: Int) -> String {
        let bytes = (0..<Wire.ipv4Length).map { String(data[start + $0]) }
        return bytes.joined(separator: ".")
    }

    private static func formatIPv6(_ data: Data, start: Int) -> String {
        let bytes = data[start..<start + Wire.ipv6Length]
        let parts = stride(from: 0, to: Wire.ipv6Length, by: Wire.ipv6GroupStride).map { i in
            let hi = UInt16(bytes[bytes.startIndex + i]) << Wire.bitsPerByte
            let lo = UInt16(bytes[bytes.startIndex + i + 1])
            return String(format: "%x", hi | lo)
        }
        return parts.joined(separator: ":")
    }

    /// readUInt16 reads a big-endian (network-order) UInt16 at `offset`. Caller must
    /// have already bounds-checked.
    private static func readUInt16(_ data: Data, at offset: Int) -> UInt16 {
        UInt16(data[offset]) << Wire.bitsPerByte | UInt16(data[offset + 1])
    }

    // MARK: - Private helpers

    private static func skipName(in data: Data, at start: Int) -> Int {
        var offset = start
        while offset < data.count {
            let length = Int(data[offset])
            if length == 0 { return offset + 1 }
            if length >= Wire.compressionPointerMarker {
                return offset + Wire.compressionPointerLength
            }
            offset += 1 + length
        }
        return offset
    }

    // RFC 1035 §3.2.2 + RFC 3596 §2.1 + RFC 2782 §2 TYPE codes the NetworkExtension
    // surfaces today. The numeric keys are the canonical wire codes; suppressing
    // no_magic_numbers across the literal is correct because the keys ARE the spec.
    // swiftlint:disable no_magic_numbers
    private static let qtypeNames: [UInt16: String] = [
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY"
    ]
    // swiftlint:enable no_magic_numbers

    private static func qtypeToString(_ qtype: UInt16) -> String {
        qtypeNames[qtype] ?? "TYPE\(qtype)"
    }
}
