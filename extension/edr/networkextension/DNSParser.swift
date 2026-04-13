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
            if length >= 0xC0 { break } // compression pointer, stop parsing
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

        // Skip header (12 bytes) + question section
        var offset = 12
        let qdcount = UInt16(data[4]) << 8 | UInt16(data[5])
        for _ in 0..<qdcount {
            offset = skipName(in: data, at: offset)
            offset += 4 // QTYPE + QCLASS
            guard offset <= data.count else { return [] }
        }

        var addresses: [String] = []
        for _ in 0..<ancount {
            guard offset < data.count else { break }
            // Skip name (may be compression pointer)
            offset = skipName(in: data, at: offset)
            guard offset + 10 <= data.count else { break }

            let rrType = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
            let rdlength = Int(UInt16(data[offset + 8]) << 8 | UInt16(data[offset + 9]))
            offset += 10 // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

            guard offset + rdlength <= data.count else { break }

            if rrType == 1 && rdlength == 4 { // A record
                let ip = "\(data[offset]).\(data[offset+1]).\(data[offset+2]).\(data[offset+3])"
                addresses.append(ip)
            } else if rrType == 28 && rdlength == 16 { // AAAA record
                let bytes = data[offset..<offset+16]
                let parts = stride(from: 0, to: 16, by: 2).map { i in
                    String(format: "%x", UInt16(bytes[bytes.startIndex + i]) << 8 | UInt16(bytes[bytes.startIndex + i + 1]))
                }
                addresses.append(parts.joined(separator: ":"))
            }

            offset += rdlength
        }

        return addresses
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

    private static func qtypeToString(_ qtype: UInt16) -> String {
        switch qtype {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 6: return "SOA"
        case 12: return "PTR"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 255: return "ANY"
        default: return "TYPE\(qtype)"
        }
    }
}
