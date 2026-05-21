// DNSParser tests: hand-rolled RFC 1035 packets exercise queryName, queryType, and
// responseAddresses against the wire shapes the network extension actually emits via
// NEDNSProxyProvider. The on-wire bytes are tiny and the parser is pure-Foundation, so
// PBT isn't a fit -- example-based tests pin the exact bytes the production code must
// accept, which is also what regressions look like in this layer.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class DNSParserTests: XCTestCase {
    // MARK: - Packet builders (kept compact so the test bodies read as assertions on
    // canonical byte sequences, not packet-construction boilerplate).

    /// header builds the 12-byte fixed DNS header. id, qdcount, ancount tunables are
    /// the only fields the parser actually consults.
    private func header(id: UInt16, qdcount: UInt16, ancount: UInt16) -> Data {
        var bytes = Data()
        bytes.append(UInt8(id >> 8)); bytes.append(UInt8(id & 0xFF))
        bytes.append(0x01); bytes.append(0x00) // flags: standard query, RD set
        bytes.append(UInt8(qdcount >> 8)); bytes.append(UInt8(qdcount & 0xFF))
        bytes.append(UInt8(ancount >> 8)); bytes.append(UInt8(ancount & 0xFF))
        bytes.append(0x00); bytes.append(0x00) // NSCOUNT
        bytes.append(0x00); bytes.append(0x00) // ARCOUNT
        return bytes
    }

    /// encodeName encodes a DNS-format name (length-prefixed labels terminated by a
    /// zero byte). E.g. "example.com" -> 0x07 e x a m p l e 0x03 c o m 0x00.
    private func encodeName(_ name: String) -> Data {
        var bytes = Data()
        for label in name.split(separator: ".") {
            let labelBytes = Array(label.utf8)
            bytes.append(UInt8(labelBytes.count))
            bytes.append(contentsOf: labelBytes)
        }
        bytes.append(0x00) // root terminator
        return bytes
    }

    /// question section: NAME + QTYPE(2) + QCLASS(2). qtype is the wire code, e.g. 1
    /// for A, 28 for AAAA.
    private func question(name: String, qtype: UInt16) -> Data {
        var bytes = encodeName(name)
        bytes.append(UInt8(qtype >> 8)); bytes.append(UInt8(qtype & 0xFF))
        bytes.append(0x00); bytes.append(0x01) // QCLASS = IN
        return bytes
    }

    /// answerRecord encodes a single resource record. NAME is a 2-byte compression
    /// pointer to offset 0x0C (the question section), matching what every real DNS
    /// resolver emits -- this exercises the parser's skipName compression-pointer
    /// branch end-to-end.
    private func answerRecord(rrType: UInt16, rdata: Data) -> Data {
        var bytes = Data()
        bytes.append(0xC0); bytes.append(0x0C)                                   // NAME pointer to header end
        bytes.append(UInt8(rrType >> 8)); bytes.append(UInt8(rrType & 0xFF))     // TYPE
        bytes.append(0x00); bytes.append(0x01)                                   // CLASS = IN
        bytes.append(0x00); bytes.append(0x00); bytes.append(0x00); bytes.append(0x3C) // TTL = 60
        let rdlen = UInt16(rdata.count)
        bytes.append(UInt8(rdlen >> 8)); bytes.append(UInt8(rdlen & 0xFF))       // RDLENGTH
        bytes.append(rdata)
        return bytes
    }

    // MARK: - queryName

    func testQueryNameSimpleDotSeparated() {
        var packet = header(id: 0x1234, qdcount: 1, ancount: 0)
        packet.append(question(name: "example.com", qtype: 1))
        XCTAssertEqual(DNSParser.queryName(from: packet), "example.com")
    }

    func testQueryNameMultiLabelSubdomain() {
        var packet = header(id: 0x1234, qdcount: 1, ancount: 0)
        packet.append(question(name: "api.fleetdm.com", qtype: 1))
        XCTAssertEqual(DNSParser.queryName(from: packet), "api.fleetdm.com")
    }

    func testQueryNameReturnsNilForCompressionPointerInQname() {
        // QNAME starts with a compression-pointer byte (0xC0). The parser refuses to
        // resolve pointers in the query section -- they would not occur in real
        // queries -- and returns nil rather than chasing the pointer.
        var packet = header(id: 0x1234, qdcount: 1, ancount: 0)
        packet.append(0xC0) // illegal first byte
        packet.append(0x0C)
        packet.append(0x00); packet.append(0x01) // QTYPE
        packet.append(0x00); packet.append(0x01) // QCLASS
        XCTAssertNil(DNSParser.queryName(from: packet))
    }

    func testQueryNameReturnsNilForEmptyPacket() {
        XCTAssertNil(DNSParser.queryName(from: Data()))
    }

    func testQueryNameReturnsNilForHeaderOnlyPacket() {
        // 12-byte header is the minimum possible packet but has no question section.
        XCTAssertNil(DNSParser.queryName(from: header(id: 0, qdcount: 0, ancount: 0)))
    }

    func testQueryNameReturnsNilWhenLabelLengthOverflowsBuffer() {
        // Claim a 100-byte label inside a buffer that has nowhere near 100 bytes
        // left. The parser must not run past the end of the buffer.
        var packet = header(id: 0x1234, qdcount: 1, ancount: 0)
        packet.append(100)
        packet.append(contentsOf: Array(repeating: 0x41, count: 5))
        XCTAssertNil(DNSParser.queryName(from: packet))
    }

    // MARK: - queryType

    func testQueryTypeRecognizesKnownTypes() {
        let cases: [(qtype: UInt16, expected: String)] = [
            (1, "A"),
            (2, "NS"),
            (5, "CNAME"),
            (6, "SOA"),
            (12, "PTR"),
            (15, "MX"),
            (16, "TXT"),
            (28, "AAAA"),
            (33, "SRV"),
            (255, "ANY")
        ]
        for testCase in cases {
            var packet = header(id: 0x1234, qdcount: 1, ancount: 0)
            packet.append(question(name: "example.com", qtype: testCase.qtype))
            XCTAssertEqual(
                DNSParser.queryType(from: packet),
                testCase.expected,
                "qtype=\(testCase.qtype) should map to \(testCase.expected)"
            )
        }
    }

    func testQueryTypeUnknownFallsBackToTypeCode() {
        // 99 is not in the canonical map, so the parser falls back to TYPE99 rather
        // than dropping the event entirely.
        var packet = header(id: 0x1234, qdcount: 1, ancount: 0)
        packet.append(question(name: "example.com", qtype: 99))
        XCTAssertEqual(DNSParser.queryType(from: packet), "TYPE99")
    }

    func testQueryTypeReturnsUnknownForEmptyOrTruncatedPacket() {
        XCTAssertEqual(DNSParser.queryType(from: Data()), "unknown")
        // 12-byte header but no question section.
        XCTAssertEqual(DNSParser.queryType(from: header(id: 0, qdcount: 0, ancount: 0)), "unknown")
    }

    // MARK: - responseAddresses

    func testResponseAddressesSingleIPv4() {
        var packet = header(id: 0x1234, qdcount: 1, ancount: 1)
        packet.append(question(name: "example.com", qtype: 1))
        packet.append(answerRecord(rrType: 1, rdata: Data([93, 184, 215, 14])))
        XCTAssertEqual(DNSParser.responseAddresses(from: packet), ["93.184.215.14"])
    }

    func testResponseAddressesMultipleIPv4() {
        // Two A records in the answer section. Order is preserved because the parser
        // walks ancount records sequentially.
        var packet = header(id: 0x1234, qdcount: 1, ancount: 2)
        packet.append(question(name: "example.com", qtype: 1))
        packet.append(answerRecord(rrType: 1, rdata: Data([10, 0, 0, 1])))
        packet.append(answerRecord(rrType: 1, rdata: Data([10, 0, 0, 2])))
        XCTAssertEqual(DNSParser.responseAddresses(from: packet), ["10.0.0.1", "10.0.0.2"])
    }

    func testResponseAddressesSingleIPv6() {
        // 2001:db8::1 = 2001:0db8:0000:0000:0000:0000:0000:0001 = 16 bytes packed.
        let ipv6Bytes: [UInt8] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        ]
        var packet = header(id: 0x1234, qdcount: 1, ancount: 1)
        packet.append(question(name: "example.com", qtype: 28))
        packet.append(answerRecord(rrType: 28, rdata: Data(ipv6Bytes)))
        // The parser emits the un-compressed colon-separated form: groups whose
        // value is 0 stay as a literal "0", not the RFC 5952 "::" double-colon
        // collapse. Pin this exact shape so detection-engine consumers downstream
        // do not have to handle both forms.
        XCTAssertEqual(DNSParser.responseAddresses(from: packet), ["2001:db8:0:0:0:0:0:1"])
    }

    func testResponseAddressesIgnoresUnknownRecordTypes() {
        // TYPE16 (TXT) has no IP rdata, so the parser returns no addresses while
        // still advancing past the record correctly. Adding a second known A record
        // after a TXT proves the offset math is right.
        var packet = header(id: 0x1234, qdcount: 1, ancount: 2)
        packet.append(question(name: "example.com", qtype: 1))
        packet.append(answerRecord(rrType: 16, rdata: Data("v=spf1".utf8)))
        packet.append(answerRecord(rrType: 1, rdata: Data([8, 8, 8, 8])))
        XCTAssertEqual(DNSParser.responseAddresses(from: packet), ["8.8.8.8"])
    }

    func testResponseAddressesEmptyForQueryOnlyPacket() {
        // A query packet (ancount=0) yields no addresses but the parser must not crash
        // when there is nothing past the question section.
        var packet = header(id: 0x1234, qdcount: 1, ancount: 0)
        packet.append(question(name: "example.com", qtype: 1))
        XCTAssertEqual(DNSParser.responseAddresses(from: packet), [])
    }

    func testResponseAddressesEmptyForUndersizedPacket() {
        // Packet shorter than the header is rejected outright.
        XCTAssertEqual(DNSParser.responseAddresses(from: Data([0x00])), [])
    }

    func testResponseAddressesEmptyWhenRdlengthLies() {
        // Header claims one answer, RR claims a 50-byte RDATA but the buffer ends.
        // The parser must bail rather than reading past the end of the buffer.
        var packet = header(id: 0x1234, qdcount: 1, ancount: 1)
        packet.append(question(name: "example.com", qtype: 1))
        // Hand-roll an RR with bogus RDLENGTH.
        packet.append(0xC0); packet.append(0x0C) // NAME pointer
        packet.append(0x00); packet.append(0x01) // TYPE=A
        packet.append(0x00); packet.append(0x01) // CLASS=IN
        packet.append(0x00); packet.append(0x00); packet.append(0x00); packet.append(0x3C) // TTL
        packet.append(0x00); packet.append(0x32) // RDLENGTH=50 (lie)
        packet.append(contentsOf: [1, 2, 3, 4])  // only 4 bytes of rdata actually here
        XCTAssertEqual(DNSParser.responseAddresses(from: packet), [])
    }
}
