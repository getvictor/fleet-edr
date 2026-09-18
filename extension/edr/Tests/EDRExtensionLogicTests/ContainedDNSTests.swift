import Foundation
@testable import EDRExtensionLogic
import XCTest

/// Tests for what the DNS proxy does with a query while the host is contained (#948). The proxy wiring (writing the answer to the
/// client flow, closing TCP flows) is exercised on edr-dev, because DNSProxyProvider imports NetworkExtension.
final class ContainedDNSTests: XCTestCase {
    private let contained = NetworkContainmentUpdate(version: 1, epoch: 1, contained: true, serverPort: 443,
                                                     serverAddresses: ["203.0.113.7"], serverNames: ["edr.example.com"])

    /// query builds a DNS query: ID 0x1234, RD set, the given labels, type A class IN, and optionally an EDNS OPT record.
    private func query(_ labels: [[UInt8]], questions: UInt16 = 1, flags: [UInt8] = [0x01, 0x00], edns: Bool = false) -> Data {
        var bytes: [UInt8] = [0x12, 0x34] + flags + [UInt8(questions >> 8), UInt8(questions & 0xFF), 0, 0, 0, 0, 0, edns ? 1 : 0]
        for label in labels {
            bytes.append(UInt8(label.count))
            bytes += label
        }
        bytes += [0, 0x00, 0x01, 0x00, 0x01]
        if edns {
            bytes += [0, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0x00, 0x00]
        }
        return Data(bytes)
    }

    private func name(_ text: String) -> [[UInt8]] {
        text.split(separator: ".").map { Array($0.utf8) }
    }

    func testAHostThatIsNotContainedForwardsEverything() {
        XCTAssertEqual(ContainedDNS.decision(for: query(name("anything.example.net")), containment: nil), .forward)
        let released = NetworkContainmentUpdate(version: 2, epoch: 1, contained: false, serverPort: 0, serverAddresses: [])
        XCTAssertEqual(ContainedDNS.decision(for: Data([1, 2, 3]), containment: released), .forward)
    }

    // spec:extension-network-response/a-contained-host-resolves-only-the-edr-server-s-name/the-server-s-name-still-resolves
    func testTheServersNameIsForwardedWhateverItsCase() {
        for spelling in ["edr.example.com", "EDR.Example.COM"] {
            let datagram = query(name(spelling))
            XCTAssertEqual(ContainedDNS.decision(for: datagram, containment: contained), .forwardQuestion(datagram),
                           "a plain query is already its header and question")
        }
    }

    // spec:extension-network-response/a-contained-host-resolves-only-the-edr-server-s-name/an-allowed-lookup-carries-only-its-question
    //
    // An allowed lookup leaves the host as its ID, opcode, recursion-desired flag and question: records, options, stray flags and bytes
    // appended after the question stay behind.
    func testAnAllowedLookupCarriesOnlyItsQuestion() {
        var padded = [UInt8](query(name("edr.example.com"), flags: [0x05, 0xF0], edns: true))
        padded += Array("exfiltrated payload".utf8)
        let expected: [UInt8] = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID, RD only, one question, no records
            0x03, 0x65, 0x64, 0x72, // "edr"
            0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // "example"
            0x03, 0x63, 0x6F, 0x6D, 0x00, // "com", root
            0x00, 0x01, 0x00, 0x01 // type A, class IN
        ]
        XCTAssertEqual(ContainedDNS.decision(for: Data(padded), containment: contained), .forwardQuestion(Data(expected)))
    }

    /// ednsQuery builds a query for the allowed name carrying one OPT record with the given size, TTL bytes and option data.
    private func ednsQuery(size: UInt16, ttl: [UInt8] = [0, 0, 0, 0], options: [UInt8] = [],
                           additional: UInt16 = 1) -> Data {
        var bytes: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                              UInt8(additional >> 8), UInt8(additional & 0xFF)]
        for label in name("edr.example.com") {
            bytes.append(UInt8(label.count))
            bytes += label
        }
        bytes += [0, 0x00, 0x01, 0x00, 0x01]
        bytes += [0, 0x00, 0x29, UInt8(size >> 8), UInt8(size & 0xFF)] + ttl
        bytes += [UInt8(options.count >> 8), UInt8(options.count & 0xFF)] + options
        return Data(bytes)
    }

    /// forwarded is the query the decision says to send, for a lookup the lifeline allows.
    private func forwarded(_ datagram: Data) -> Data? {
        guard case let .forwardQuestion(sent) = ContainedDNS.decision(for: datagram, containment: contained) else { return nil }
        return sent
    }

    /// expected is the header and question of an allowed lookup, optionally followed by a rebuilt OPT record of the given size.
    private func expectedForward(udpSize: UInt16?) -> Data {
        var bytes: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, udpSize == nil ? 0 : 1]
        bytes += [0x03, 0x65, 0x64, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00]
        bytes += [0x00, 0x01, 0x00, 0x01]
        if let udpSize {
            bytes += [0, 0x00, 0x29, UInt8(udpSize >> 8), UInt8(udpSize & 0xFF), 0, 0, 0, 0, 0, 0]
        }
        return Data(bytes)
    }

    // spec:extension-network-response/a-contained-host-resolves-only-the-edr-server-s-name/an-allowed-lookup-keeps-a-rebuilt-udp-size
    //
    // Without an OPT record the resolver answers within 512 octets, so an allowed name with many addresses comes back truncated and the
    // stub retries over TCP, which is closed while contained: the name stops resolving (issue #1072). The rebuilt record is this
    // proxy's own and carries a size and nothing else.
    func testAnAllowedLookupKeepsAUDPSizeWhenTheClientOfferedOne() {
        XCTAssertEqual(forwarded(ednsQuery(size: 4096)), expectedForward(udpSize: 1232),
                       "the size is capped at what traverses the internet unfragmented")
        XCTAssertEqual(forwarded(ednsQuery(size: 1232)), expectedForward(udpSize: 1232))
        XCTAssertEqual(forwarded(ednsQuery(size: 800)), expectedForward(udpSize: 800),
                       "a client asking for less than the cap is not given more than it can take")
        XCTAssertEqual(forwarded(ednsQuery(size: 12)), expectedForward(udpSize: 512),
                       "and a nonsense size is floored rather than passed on")
    }

    // spec:extension-network-response/a-contained-host-resolves-only-the-edr-server-s-name/an-allowed-lookup-carries-only-its-question
    //
    // Everything the client can put in an OPT record beyond the size is left behind, and anything this does not recognise takes the
    // query back to the header and question alone rather than being forwarded unread.
    func testAnOPTRecordCarryingAnythingElseIsNotForwarded() {
        let cases: [(String, Data)] = [
            ("an option", ednsQuery(size: 1232, options: [0x00, 0x0A, 0x00, 0x02, 0xAB, 0xCD])),
            ("the DNSSEC-OK bit", ednsQuery(size: 1232, ttl: [0, 0, 0x80, 0])),
            ("a reserved flag", ednsQuery(size: 1232, ttl: [0, 0, 0x00, 0x01])),
            ("an EDNS version this does not know", ednsQuery(size: 1232, ttl: [0, 1, 0, 0])),
            ("an extended RCODE", ednsQuery(size: 1232, ttl: [1, 0, 0, 0])),
            ("a header counting records it does not carry", ednsQuery(size: 1232, additional: 2))
        ]
        for (what, datagram) in cases {
            XCTAssertEqual(forwarded(datagram), expectedForward(udpSize: nil), "\(what) leaves the query without an OPT record")
        }
    }

    // A record that is not an OPT, and a second question's worth of bytes, are both left behind: only the shape this reads is kept.
    func testARecordThatIsNotAnOPTIsNotForwarded() {
        var bytes = [UInt8](ednsQuery(size: 1232))
        bytes[bytes.count - 10] = 0x00
        bytes[bytes.count - 9] = 0x01 // type A where the OPT type belongs
        XCTAssertEqual(forwarded(Data(bytes)), expectedForward(udpSize: nil))
    }

    // spec:extension-network-response/a-contained-host-resolves-only-the-edr-server-s-name/any-other-name-is-refused-locally
    func testAnyOtherNameIsAnsweredRefusedWithTheQuestionAndNoRecords() {
        let decision = ContainedDNS.decision(for: query(name("exfil.attacker.example"), edns: true), containment: contained)
        var expected: [UInt8] = [0x12, 0x34, 0x81, 0x85, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name("exfil.attacker.example") {
            expected.append(UInt8(label.count))
            expected += label
        }
        expected += [0, 0x00, 0x01, 0x00, 0x01]
        XCTAssertEqual(decision, .answer(Data(expected)), "same ID, QR and RD, RA with RCODE 5, the question, no EDNS record")
    }

    func testAServerNameSplitAcrossAnOddLabelIsRefused() {
        let dotted = [Array("edr.example".utf8), Array("com".utf8)]
        guard case .answer = ContainedDNS.decision(for: query(dotted), containment: contained) else {
            return XCTFail("a label carrying a dot must not match the server's name")
        }
        guard case .answer = ContainedDNS.decision(for: query(name("sub.edr.example.com")), containment: contained) else {
            return XCTFail("a subdomain of the server is another name")
        }
    }

    func testAContainmentWithNoNamesRefusesEveryName() {
        let ipOnly = NetworkContainmentUpdate(version: 1, epoch: 1, contained: true, serverPort: 443, serverAddresses: ["203.0.113.7"])
        guard case .answer = ContainedDNS.decision(for: query(name("edr.example.com")), containment: ipOnly) else {
            return XCTFail("a lifeline of addresses alone resolves nothing")
        }
    }

    func testWhatIsNotASingleWellFormedQueryIsDropped() {
        let cases: [(String, Data)] = [
            ("a response", query(name("edr.example.com"), flags: [0x81, 0x80])),
            ("two questions", query(name("edr.example.com"), questions: 2)),
            ("no question", query([], questions: 0)),
            ("shorter than a header", Data([0x12, 0x34, 0x01])),
            ("a question past the end", Data([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0x61])),
            ("a question without its type and class", Data([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0x61, 0, 0x00])),
            ("a compression pointer", Data([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1])),
            ("a name over 255 octets", query([[UInt8]](repeating: [UInt8](repeating: 0x61, count: 63), count: 4))),
            ("a reserved label type", Data([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0x40] + [UInt8](repeating: 0x61, count: 64)
                + [0, 0, 1, 0, 1]))
        ]
        for (why, datagram) in cases {
            XCTAssertEqual(ContainedDNS.decision(for: datagram, containment: contained), .drop, why)
        }
    }

    // MARK: names in the containment document

    func testDecodeNormalizesNamesAndRefusesUnusableOnes() {
        let good = NetworkContainment.decode(Data(#"""
        {"version":1,"contained":true,"server":{"port":443,"addresses":["203.0.113.7"],"names":["EDR.Example.com."]}}
        """#.utf8))
        XCTAssertEqual(good?.serverNames, ["edr.example.com"])
        let refused: [(String, String)] = [
            ("an empty name", #"[""]"#),
            ("a trailing dot alone", #"["."]"#),
            ("a trailing hyphen", #"["edr-.example.com"]"#),
            ("a label with a space", #"["edr example.com"]"#),
            ("a leading hyphen", #"["-edr.example.com"]"#),
            ("an empty label", #"["edr..example.com"]"#),
            ("a label over 63", "[\"\(String(repeating: "a", count: 64)).com\"]"),
            ("too many names", #"["a.com","b.com","c.com","d.com","e.com"]"#)
        ]
        for (why, names) in refused {
            let doc = #"{"version":1,"contained":true,"server":{"port":443,"addresses":["203.0.113.7"],"names":"# + names + "}}"
            XCTAssertNil(NetworkContainment.decode(Data(doc.utf8)), why)
        }
    }

    func testAChangedNameIsALifelineRefresh() {
        let renamed = NetworkContainmentUpdate(version: 1, epoch: 1, contained: true, serverPort: 443,
                                               serverAddresses: ["203.0.113.7"], serverNames: ["proxy.corp"])
        XCTAssertTrue(renamed.refreshesLifeline(contained))
    }
}
