import EndpointSecurity
import Foundation

// CDHashHex.swift carries the pure helpers ESFSubscriber.swift uses to extract a string CDHash identifier and decide
// whether a target runs under Apple's Hardened Runtime. Extracted from ESFSubscriber.swift so that file stays under
// SwiftLint's file_length cap; the helpers are pure and have no class state, so file scope is the natural home.

/// csRuntimeFlag is the codesigning_flags bit set when a binary runs under Apple's Hardened Runtime. Defined here (rather than
/// imported from <kern/cs_blobs.h>) because the Swift bridging headers do not surface the constant directly; the literal value
/// is stable per the public macOS code-signing documentation. Lowercased to satisfy SwiftLint's identifier_name rule (CS_RUNTIME
/// would be the literal C symbol but Swift conventions reject all-caps identifiers).
private let csRuntimeFlag: UInt32 = 0x0001_0000

/// isHardenedRuntime reports whether the codesigning_flags bitfield indicates Apple's Hardened Runtime. CDHASH rules only match
/// hardened-runtime processes because on non-hardened processes the kernel maps pages lazily and does not re-verify them post-load,
/// which makes the CDHash ESF reports at exec an unreliable identity for the bytes that will eventually execute. This diverges from
/// Santa, which enforces CDHASH on any signed binary regardless of the runtime flag; a migrating Santa admin should expect a CDHASH
/// rule to no-op here against a non-hardened target until that target is rebuilt with the Hardened Runtime flag.
func isHardenedRuntime(flags: UInt32) -> Bool {
    return (flags & csRuntimeFlag) != 0
}

/// hexCharsPerByte is the fixed expansion ratio of a byte to its 2-char lowercase hex representation. Extracted so the capacity
/// reserve in cdhashHexString is self-documenting (SwiftLint's no_magic_numbers rule would otherwise flag the literal `2`).
private let hexCharsPerByte = 2

/// hexDigitsLowercase is the lookup table cdhashHexString walks instead of calling String(format:"%02x", b). The format-string path
/// bridges to Foundation and parses the format spec on every call; this matters because the helper runs inside AUTH_EXEC's
/// kernel-deadline window. The table is private so it doesn't pollute symbol search at the module level.
private let hexDigitsLowercase: [Character] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"
]

/// hexLowNibbleMask is the bitmask used to extract the low 4 bits of a byte when looking up its hex digit in the
/// hexDigitsLowercase table. Named so the no_magic_numbers SwiftLint rule doesn't flag the literal 0x0f.
private let hexLowNibbleMask: UInt8 = 0x0f

// swiftlint:disable large_tuple
//
// cdhashHexString lowercases-hex the 20-byte CDHash array from es_process_t.cdhash into the 40-char string the server's validator
// + the snapshot's cdhashRules map index on. Returns nil when the cdhash is all zero (es_process_t conventions: unsigned binaries
// report a zeroed cdhash, which is not a real identity).
//
// The parameter is a 20-element tuple because the C surface (es_process_t.cdhash) is a fixed-size array that Swift imports as a
// homogeneous tuple. The large_tuple lint is disabled around this declaration because the shape is dictated by the ESF SDK and
// cannot be reshaped without breaking the C bridge.
func cdhashHexString(from cdhash: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                                    UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)) -> String? {
    var bytes = cdhash
    return withUnsafeBytes(of: &bytes) { raw -> String? in
        // All-zero cdhash means "no real CDHash present": unsigned or otherwise unverifiable. Return nil so the precedence walker
        // skips the CDHASH map for this exec rather than matching a rule whose identifier is "00…00" by coincidence.
        if raw.allSatisfy({ $0 == 0 }) {
            return nil
        }
        var s = ""
        s.reserveCapacity(raw.count * hexCharsPerByte)
        for b in raw {
            s.append(hexDigitsLowercase[Int(b >> 4)])
            s.append(hexDigitsLowercase[Int(b & hexLowNibbleMask)])
        }
        return s
    }
}
// swiftlint:enable large_tuple
