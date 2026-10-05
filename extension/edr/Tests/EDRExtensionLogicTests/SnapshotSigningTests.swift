// The startup snapshot's signature for a process that predates the extension: the mapping from signing information to the
// exec event's shape, the guard against a reused pid, and a real read of a running Apple binary.

@testable import EDRExtensionLogic
import Darwin
import Foundation
import Security
import XCTest

final class SnapshotSigningTests: XCTestCase {
    // spec:endpoint-event-collection/a-snapshot-exec-carries-the-running-process-s-signature/an-apple-daemon-carries-its-signature
    func testAnAppleBinaryIsReportedAsAPlatformBinaryWithNoTeam() {
        let flags: UInt32 = SnapshotSigning.platformBinaryFlag | 0x1
        let signing = SnapshotSigning.codeSigning(from: [
            kSecCodeInfoIdentifier as String: "com.apple.mds",
            kSecCodeInfoStatus as String: NSNumber(value: flags)
        ])
        XCTAssertEqual(signing, CodeSigning(teamID: "", signingID: "com.apple.mds", flags: flags, isPlatformBinary: true))
    }

    func testADeveloperIDBinaryCarriesItsTeam() {
        let signing = SnapshotSigning.codeSigning(from: [
            kSecCodeInfoIdentifier as String: "us.zoom.updater",
            kSecCodeInfoTeamIdentifier as String: "BJ4HAAB9B3",
            kSecCodeInfoStatus as String: NSNumber(value: UInt32(0x1))
        ])
        XCTAssertEqual(signing, CodeSigning(teamID: "BJ4HAAB9B3", signingID: "us.zoom.updater", flags: 0x1, isPlatformBinary: false))
    }

    // spec:endpoint-event-collection/a-snapshot-exec-carries-the-running-process-s-signature/an-unsigned-process-carries-no-signature
    func testAnUnsignedProcessHasNoSignature() {
        XCTAssertNil(SnapshotSigning.codeSigning(from: [kSecCodeInfoTeamIdentifier as String: "BJ4HAAB9B3"]))
        XCTAssertNil(SnapshotSigning.codeSigning(from: [kSecCodeInfoIdentifier as String: ""]))
    }

    // spec:endpoint-event-collection/a-snapshot-exec-carries-the-running-process-s-signature/invalid-code-carries-no-identity
    func testCodeTheKernelNoLongerValidatesCarriesNoIdentity() {
        XCTAssertNil(SnapshotSigning.codeSigning(from: [
            kSecCodeInfoIdentifier as String: "us.zoom.updater",
            kSecCodeInfoTeamIdentifier as String: "BJ4HAAB9B3",
            kSecCodeInfoStatus as String: NSNumber(value: SnapshotSigning.platformBinaryFlag)
        ]), "a team and signing id are not attributed to code whose signature the kernel no longer holds valid")
    }

    // spec:endpoint-event-collection/a-snapshot-exec-carries-the-running-process-s-signature/a-reused-pid-gets-no-signature
    func testAReusedPidIsNotGivenTheListedProcessSignature() {
        let listed = timeval(tv_sec: 1_791_030_436, tv_usec: 491_552)
        XCTAssertTrue(SnapshotSigning.sameStartTime(listed, listed))
        XCTAssertFalse(SnapshotSigning.sameStartTime(listed, timeval(tv_sec: 1_791_030_436, tv_usec: 491_553)), "a later process")
        XCTAssertFalse(SnapshotSigning.sameStartTime(listed, nil), "the process is gone")
    }

    // A real read: a running Apple binary comes back with its identifier and the platform bit, and a start time that is not the
    // process's own yields nothing.
    func testReadsARunningAppleBinary() throws {
        let sleeper = Process()
        sleeper.executableURL = URL(fileURLWithPath: "/bin/sleep")
        sleeper.arguments = ["30"]
        try sleeper.run()
        defer { sleeper.terminate() }
        let pid = sleeper.processIdentifier
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        XCTAssertEqual(proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size), size)
        let started = timeval(tv_sec: Int(info.pbi_start_tvsec), tv_usec: Int32(info.pbi_start_tvusec))

        let signing = try XCTUnwrap(SnapshotSigning.live(pid: pid, startTime: started, path: "/bin/sleep"))
        XCTAssertEqual(signing.signingID, "com.apple.sleep")
        XCTAssertTrue(signing.isPlatformBinary)
        XCTAssertEqual(signing.teamID, "")

        let earlier = timeval(tv_sec: started.tv_sec - 1, tv_usec: started.tv_usec)
        XCTAssertNil(SnapshotSigning.live(pid: pid, startTime: earlier, path: "/bin/sleep"), "a different process now holds the pid")
        XCTAssertNil(SnapshotSigning.live(pid: pid, startTime: started, path: "/usr/bin/true"),
                     "the process now runs another program than the one listed")
    }
}
