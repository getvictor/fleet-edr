import Foundation

/// Minimal RFC 1035 DNS packet parser for extracting query name, type, and response addresses.
/// All parsing is best-effort -- malformed packets return nil/empty rather than crashing.
enum DNSParser {
    /// Extracts the first query name from a DNS packet.
    static func queryName(from data: Data) -> String? {
        // DNS header is 12 bytes. QDCOUNT at offset 4-5.
        guard data.count > 12 else { return nil }
        let qdcount = UInt16(data[4]) << 8 | UInt16(data[5])
        guard qdcount > 0 else { return nil }

        var offset = 12
        var labels: [String] = []

        while offset < data.count {
            let length = Int(data[offset])
            offset += 1

            if length == 0 { break } // end of name
            if length >= 0xC0 { return nil } // compression pointer -- we don't resolve it
            guard offset + length <= data.count else { return nil }

            let label = String(data: data[offset..<offset + length], encoding: .utf8) ?? ""
            labels.append(label)
            offset += length
        }

        return labels.isEmpty ? nil : labels.joined(separator: ".")
    }

    /// Extracts the query type string from a DNS packet.
    static func queryType(from data: Data) -> String {
        // Find end of QNAME (first zero-length label after header)
        guard data.count > 12 else { return "unknown" }
        var offset = 12
        while offset < data.count {
            let length = Int(data[offset])
            offset += 1
            if length == 0 { break }
            if length >= 0xC0 { offset += 1; break } // compression pointer (2 bytes total)
            offset += length
        }

        // QTYPE is 2 bytes after QNAME
        guard offset + 2 <= data.count else { return "unknown" }
        let qtype = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        return qtypeToString(qtype)
    }

    /// Extracts A and AAAA record addresses from a DNS response packet.
    static func responseAddresses(from data: Data) -> [String] {
        guard data.count > 12 else { return [] }

        let ancount = UInt16(data[6]) << 8 | UInt16(data[7])
        guard ancount > 0 else { return [] }

        let qdcount = UInt16(data[4]) << 8 | UInt16(data[5])
        guard let questionsEnd = skipQuestions(in: data, count: qdcount, startOffset: 12) else {
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
            offset += 4 // QTYPE + QCLASS
            guard offset <= data.count else { return nil }
        }
        return offset
    }

    /// Parses a single answer record. Returns the address (if A/AAAA) and the new offset.
    private static func parseAnswer(in data: Data, at start: Int) -> (String?, Int)? {
        guard start < data.count else { return nil }
        let afterName = skipName(in: data, at: start)
        guard afterName + 10 <= data.count else { return nil }

        let rrType = UInt16(data[afterName]) << 8 | UInt16(data[afterName + 1])
        let rdlength = Int(UInt16(data[afterName + 8]) << 8 | UInt16(data[afterName + 9]))
        let rdataStart = afterName + 10 // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        guard rdataStart + rdlength <= data.count else { return nil }

        let address = parseRecordData(in: data, type: rrType, start: rdataStart, length: rdlength)
        return (address, rdataStart + rdlength)
    }

    private static func parseRecordData(in data: Data, type rrType: UInt16, start: Int, length: Int) -> String? {
        if rrType == 1 && length == 4 { // A record
            return "\(data[start]).\(data[start+1]).\(data[start+2]).\(data[start+3])"
        }
        if rrType == 28 && length == 16 { // AAAA record
            let bytes = data[start..<start+16]
            let parts = stride(from: 0, to: 16, by: 2).map { i in
                String(format: "%x", UInt16(bytes[bytes.startIndex + i]) << 8 | UInt16(bytes[bytes.startIndex + i + 1]))
            }
            return parts.joined(separator: ":")
        }
        return nil
    }

    // MARK: - Private helpers

    private static func skipName(in data: Data, at start: Int) -> Int {
        var offset = start
        while offset < data.count {
            let length = Int(data[offset])
            if length == 0 { return offset + 1 }
            if length >= 0xC0 { return offset + 2 } // compression pointer
            offset += 1 + length
        }
        return offset
    }

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

    private static func qtypeToString(_ qtype: UInt16) -> String {
        qtypeNames[qtype] ?? "TYPE\(qtype)"
    }
}
