import EndpointSecurity
import Foundation

/// Read an es_string_token_t into a Swift String using the token's
/// explicit length rather than scanning for a NUL terminator. The
/// Endpoint Security API does NOT guarantee that the underlying byte
/// buffer is NUL-terminated, so `String(cString: token.data)` can
/// overread into adjacent memory in the worst case and produce garbage
/// in the typical case. Use this helper everywhere a Swift String is
/// derived from an es_string_token_t — paths, team IDs, signing IDs.
/// Returns the empty string when the token has no payload (data is
/// nil or length is zero).
@inline(__always)
func esTokenString(_ token: es_string_token_t) -> String {
    guard let buf = token.data, token.length > 0 else {
        return ""
    }
    return String(decoding: UnsafeRawBufferPointer(start: buf, count: token.length), as: UTF8.self)
}
