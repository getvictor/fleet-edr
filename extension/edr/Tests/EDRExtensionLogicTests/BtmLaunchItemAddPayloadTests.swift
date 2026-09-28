// The btm_launch_item_add wire shape for an SMAppService item, kept apart from EventSerializerTests, which is at its length caps.

import Foundation
@testable import EDRExtensionLogic
import XCTest

final class BtmLaunchItemAddPayloadTests: XCTestCase {
    // A login item, in the shape captured on a VM (issue #1167): SMAppService names the item relative to the registering app, which
    // rides as app_url, and BTM reports no executable. A legacy registration has no app, and the key is omitted rather than null.
    func testBtmLaunchItemAddPayloadCarriesTheRegisteringApp() throws {
        let loginItem = BtmLaunchItemAddPayload(
            itemType: "login_item",
            itemPath: "Contents/Library/LoginItems/EdrLoginTestHelper.app",
            appURL: "file:///Users/victor/Applications/EdrLoginTest.app/",
            executablePath: "",
            legacy: false,
            managed: false,
            uid: 501,
            executableCodeSigning: nil,
            instigatorPid: 0,
            instigatorCodeSigning: nil
        )
        let json = String(data: try JSONEncoder().encode(loginItem), encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"app_url\":"), "missing app_url in: \(json)")
        let decoded = try JSONDecoder().decode(BtmLaunchItemAddPayload.self, from: try JSONEncoder().encode(loginItem))
        XCTAssertEqual(decoded.appURL, loginItem.appURL)

        let legacy = BtmLaunchItemAddPayload(
            itemType: "daemon", itemPath: "file:///Library/LaunchDaemons/x.plist", appURL: nil, executablePath: "/tmp/d",
            legacy: true, managed: false, uid: 0, executableCodeSigning: nil, instigatorPid: 0, instigatorCodeSigning: nil
        )
        XCTAssertFalse((String(data: try JSONEncoder().encode(legacy), encoding: .utf8) ?? "").contains("app_url"))
    }
}
