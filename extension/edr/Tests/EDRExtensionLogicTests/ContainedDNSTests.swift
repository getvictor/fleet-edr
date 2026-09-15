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
