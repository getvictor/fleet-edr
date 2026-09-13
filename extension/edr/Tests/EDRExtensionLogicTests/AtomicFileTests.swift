import Foundation
@testable import EDRExtensionLogic
import XCTest

final class AtomicFileTests: XCTestCase {
    func testWriteCreatesTheDirectoryAndReplacesTheFile() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("nested/store.json").path

        try AtomicFile.write(Data("first".utf8), toPath: path)
        try AtomicFile.write(Data("second".utf8), toPath: path)

        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), Data("second".utf8))
    }

    func testWriteThrowsWhenTheDirectoryCannotBeCreated() throws {
        let blocker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: blocker) }
        try Data("a file where a directory should be".utf8).write(to: blocker)

        XCTAssertThrowsError(try AtomicFile.write(Data("x".utf8), toPath: blocker.appendingPathComponent("store.json").path))
    }
}
