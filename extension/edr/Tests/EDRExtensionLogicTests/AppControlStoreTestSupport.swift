// Shared fixtures for the ApplicationControlStore test classes. The gate-behaviour tests
// (ApplicationControlStoreTests) and the #322 epoch / re-sync tests
// (ApplicationControlStoreResyncTests) live in separate files so each class stays under SwiftLint's per-type and per-file
// length budgets; this base class owns the per-test store factory and the JSON document builder both depend on so the
// fixtures are not duplicated across the two files.

import Foundation
@testable import EDRExtensionLogic
import XCTest

/// RuleSpec is a named record for the document() helper's `rules` argument. A 3-tuple would trip SwiftLint's
/// large_tuple rule (max 2 members); a struct also reads better at the call sites and lets us name the field at use.
struct RuleSpec {
    let type: String
    let identifier: String
    let ruleID: String
}

/// AppControlStoreTestCase is the shared XCTestCase base for the ApplicationControlStore suites. Subclasses inherit the
/// store factory + document builder; they add only their own test methods.
class AppControlStoreTestCase: XCTestCase {
    /// makeStore returns a fresh ApplicationControlStore with a temp on-disk
    /// policy path. The path is unique per call so concurrent / parallelized
    /// test runs cannot stomp each other's persist files. The teardown block
    /// removes the file (and any parent directory the persist code created).
    func makeStore() -> ApplicationControlStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("AppControlTests-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("application-control.json")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }
        return ApplicationControlStore(storagePath: url.path)
    }

    /// waitForFile polls for the file at `path` to exist within `deadline`. The
    /// store's persistQueue is private, so we cannot synchronize on it directly;
    /// the file-exists predicate is what the apply→persist→load round-trip test
    /// needs to gate on before loading the snapshot back from disk. 2s is the
    /// same budget testStartLazyFillPopulatesCacheEventually uses for the same
    /// pattern.
    @discardableResult
    func waitForFile(at path: String, deadline: TimeInterval = 2) -> Bool {
        let stop = Date().addingTimeInterval(deadline)
        while Date() < stop {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return FileManager.default.fileExists(atPath: path)
    }

    /// document builds an ApplicationControlDocument as on-the-wire JSON bytes. `epoch` is optional so existing callers
    /// produce a payload with no `policy_epoch` key (decoded as 0, the legacy / pre-#322 path); the regression tests pass an
    /// explicit epoch to exercise the restore-resync gate.
    func document(policyID: Int64, version: Int64, rules: [RuleSpec], epoch: Int64? = nil) -> Data {
        let ruleObjects = rules.map { rule in
            """
            {
              "rule_id": "\(rule.ruleID)",
              "rule_type": "\(rule.type)",
              "identifier": "\(rule.identifier)",
              "action": "BLOCK",
              "enforcement": "PROTECT",
              "severity": "high"
            }
            """
        }
        let joined = ruleObjects.joined(separator: ",")
        let epochLine = epoch.map { "  \"policy_epoch\": \($0),\n" } ?? ""
        let json = """
        {
          "policy_id": \(policyID),
          "policy_version": \(version),
        \(epochLine)  "rules": [\(joined)]
        }
        """
        return Data(json.utf8)
    }
}
