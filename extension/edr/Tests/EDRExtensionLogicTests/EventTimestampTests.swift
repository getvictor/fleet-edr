// Envelope timestamp semantics: `timestamp_ns` reports when the KERNEL saw the event, not when this process finished handling it.
//
// The distinction is the whole of issue #710. Sampling the wall clock at serialization records handler latency, and on a loaded host
// that was measured at 701ms for exec, which is enough to place a process AFTER the network flow it produced. The server correlates
// flows to processes by comparing these stamps, so it then finds no process and reports nothing at all.

@testable import EDRExtensionLogic
import XCTest

final class EventTimestampTests: XCTestCase {

    private struct StubPayload: Codable, Sendable {
        let pid: Int
    }

    private func timestampNs(of data: Data) throws -> UInt64 {
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        return try XCTUnwrap(object["timestamp_ns"] as? UInt64)
    }

    // MARK: Conversion

    func test_kernelEventTimeNs_combines_seconds_and_nanoseconds() {
        XCTAssertEqual(kernelEventTimeNs(timespec(tv_sec: 0, tv_nsec: 0)), 0)
        XCTAssertEqual(kernelEventTimeNs(timespec(tv_sec: 1, tv_nsec: 0)), 1_000_000_000)
        XCTAssertEqual(kernelEventTimeNs(timespec(tv_sec: 0, tv_nsec: 1)), 1)
        XCTAssertEqual(kernelEventTimeNs(timespec(tv_sec: 2, tv_nsec: 500_000_000)), 2_500_000_000)
    }

    // The conversion is only useful if it lands on the same clock the rest of the system compares against. A kernel stamp that is not
    // CLOCK_REALTIME nanoseconds would correlate against process rows even worse than the handler-time stamp it replaces.
    func test_kernelEventTimeNs_is_on_the_same_realtime_base_the_server_compares_against() {
        var now = timespec()
        clock_gettime(CLOCK_REALTIME, &now)
        let converted = kernelEventTimeNs(now)
        let sampled = UInt64(clock_gettime_nsec_np(CLOCK_REALTIME))
        // Both readings are the same clock taken microseconds apart, so they agree to well within a second.
        XCTAssertLessThan(sampled > converted ? sampled - converted : converted - sampled, 1_000_000_000)
    }

    // MARK: Envelope

    // spec:endpoint-event-collection/canonical-event-envelope/a-kernel-event-is-stamped-with-the-kernel-s-own-event-time
    func test_spec_endpoint_event_collection_canonical_event_envelope_a_kernel_event_is_stamped_with_the_kernel_s_own_event_time()
        throws {
        let serializer = EventSerializer()
        // An instant safely in the past, standing in for the kernel's report of an event this handler is only now getting to.
        let kernelTime: UInt64 = 1_700_000_000_123_456_789

        let data = try XCTUnwrap(serializer.serialize(eventType: "exec", payload: StubPayload(pid: 42), kernelTimeNs: kernelTime))

        XCTAssertEqual(try timestampNs(of: data), kernelTime,
                       "the envelope must carry the kernel's instant, not the instant serialize ran")
    }

    // spec:endpoint-event-collection/canonical-event-envelope/an-event-with-no-kernel-message-behind-it-is-stamped-when-produced
    func test_spec_endpoint_event_collection_canonical_event_envelope_an_event_with_no_kernel_message_behind_it_is_stamped_when_produced()
        throws {
        let serializer = EventSerializer()
        let before = UInt64(clock_gettime_nsec_np(CLOCK_REALTIME))

        let data = try XCTUnwrap(serializer.serialize(eventType: "application_control_resync", payload: StubPayload(pid: 1)))

        let after = UInt64(clock_gettime_nsec_np(CLOCK_REALTIME))
        let stamped = try timestampNs(of: data)
        XCTAssertGreaterThanOrEqual(stamped, before, "a state read with no kernel event behind it is stamped when it is produced")
        XCTAssertLessThanOrEqual(stamped, after)
    }
}
