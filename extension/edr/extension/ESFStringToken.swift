import EndpointSecurity
import Foundation

/// Read an es_string_token_t into a Swift String using the token's
/// explicit length rather than scanning for a NUL terminator. The
/// Endpoint Security API does NOT guarantee that the underlying byte
/// buffer is NUL-terminated, so `String(cString: token.data)` can
/// overread into adjacent memory in the worst case and produce garbage
/// in the typical case. Use this helper everywhere a Swift String is
/// derived from an es_string_token_t — paths, team IDs, signing IDs.
///
/// Returns the empty string when the token has no payload (data is
/// nil or length is zero) OR when the bytes are not valid UTF-8. The
/// failable `String(bytes:encoding:)` initializer is preferred over
/// `String(decoding:as:)` per SwiftLint's optional_data_string_conversion
/// rule: an invalid-UTF-8 byte run should surface as "unknown" (empty
/// string) rather than as a path with U+FFFD replacement characters,
/// which a downstream rule comparison might miscompare against the
/// admin-provided canonical form.
///
/// Implementation note: es_string_token_t.data is UnsafePointer<CChar>
/// (Int8), but String(bytes:encoding:) requires a sequence of UInt8.
/// UnsafeRawBufferPointer reinterprets the same memory as raw bytes
/// without an allocation or a copy; its Element is UInt8, which is
/// what the failable initializer wants.
@inline(__always)
func esTokenString(_ token: es_string_token_t) -> String {
    guard let buf = token.data, token.length > 0 else {
        return ""
    }
    let bytes = UnsafeRawBufferPointer(start: buf, count: token.length)
    return String(bytes: bytes, encoding: .utf8) ?? ""
}
