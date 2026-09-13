import Foundation

/// AtomicFile is the one way the extension persists a pushed document: the application-control snapshot and the watched-path set.
/// Shared so the two stores cannot drift apart on how a write survives a crash or on what a missing directory means.
enum AtomicFile {
    /// write creates the file's directory if needed and replaces the file with data atomically. Data.write(to:options: .atomic) writes
    /// a temporary file and renames it over the destination, so a crash mid-write leaves the previous file intact rather than a torn
    /// one, and there is no moment when the destination is missing.
    static func write(_ data: Data, toPath path: String) throws {
        let url = URL(fileURLWithPath: path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }
}
