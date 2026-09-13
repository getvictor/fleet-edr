package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CommandTypeSetWatchedPaths is the command that carries the watched-path set to a host (issue #998). The agent forwards its payload
// to the Endpoint Security extension, whose file-tamper client watches these paths on top of the ones built into it. Stable wire
// string; renaming it breaks every deployed agent.
const CommandTypeSetWatchedPaths = "set_watched_paths"

// WatchedPathMatch is how a watched path covers files. The extension maps each value onto an Endpoint Security target mute type.
type WatchedPathMatch string

const (
	// WatchedPathLiteral covers exactly the file at the path.
	WatchedPathLiteral WatchedPathMatch = "literal"
	// WatchedPathPrefix covers every path that starts with it, at any depth.
	WatchedPathPrefix WatchedPathMatch = "prefix"
)

// WatchedPath is one entry in the watched-path set. The JSON tags are the wire shape the extension decodes (WatchedPaths.swift).
type WatchedPath struct {
	Path  string           `json:"path"`
	Match WatchedPathMatch `json:"match"`
}

// SetWatchedPathsPayload is the payload of a set_watched_paths command. Version is the set's server version, reported back by the
// agent so an operator can see which set a host took. Epoch is the set's update time in Unix microseconds.
//
// The extension applies a set only when its version or its epoch is ahead of the last one it accepted, because commands can reach a
// host out of order. Epoch is what keeps that ordering true after a database restore sends version backwards: the next change is
// stamped with a later wall-clock time than anything before the restore, the same reason application control carries policy_epoch.
type SetWatchedPathsPayload struct {
	Version int64         `json:"version"`
	Epoch   int64         `json:"epoch"`
	Paths   []WatchedPath `json:"paths"`
}

// WatchedPathSet is the stored set, as the REST API reports it.
type WatchedPathSet struct {
	// Version starts at 0, the set no operator has changed, and advances by one on every change.
	Version int64         `json:"version"`
	Paths   []WatchedPath `json:"paths"`
	// UpdatedAt and UpdatedBy are zero until the first change.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// BuiltInWatchedPaths are the paths the extension watches whatever the set holds, mirroring WatchedPaths.builtIn in the extension.
// The set adds to these and cannot remove them. Reported so the console can say what is always watched; the extension, not this
// list, is what enforces it.
var BuiltInWatchedPaths = []WatchedPath{
	{Path: "/etc/sudoers", Match: WatchedPathLiteral},
	{Path: "/etc/sudoers.d/", Match: WatchedPathPrefix},
}

// MaxWatchedPaths bounds the set. Every entry is a mute the file-tamper client holds, two for a path under a firmlinked root, and a
// set this size already covers the uses the issue names (canaries, credential stores, a handful of integrity-monitored directories)
// many times over.
const MaxWatchedPaths = 32

// MaxWatchedPathBytes bounds one path: the macOS PATH_MAX of 1024 counts the terminating NUL of the C string es_mute_path takes, so the
// longest path it can mute is one byte shorter.
const MaxWatchedPathBytes = 1023

// MaxWatchedPathSetBytes bounds the whole set as the server encodes it into a command payload. The fan-out repeats that payload on every
// row of a batched insert of up to 256 hosts, so this keeps one statement near 2 MiB, inside the 4 MiB max_allowed_packet the
// server is designed to work under. Real watched paths are short; the bound only bites on a set of many maximum-length paths, which
// MaxWatchedPaths and MaxWatchedPathBytes alone would allow at over 30 KiB.
const MaxWatchedPathSetBytes = 8 * 1024

// ErrInvalidWatchedPaths is returned for a set the server refuses. The wrapped message names the entry and the reason, and the REST
// handler returns it to the operator.
var ErrInvalidWatchedPaths = errors.New("invalid watched paths")

// ValidateWatchedPaths checks a proposed set. It is the one place the set is validated: the agent checks only the envelope and the
// extension applies what it is given.
//
// A path must be absolute, clean (no empty, "." or ".." segment), within MaxWatchedPathBytes in its /private spelling (the one the
// extension mutes and the kernel reports for /etc, /tmp and /var), and free of ASCII control characters
// (NUL included, which would truncate the path the kernel receives). A prefix
// names a directory, so it ends in "/", and it must lie below a top-level directory: a prefix such as "/Users/" or "/Library/" would
// put every write under that tree on the wire, which is the firehose ADR-0008 removed. A literal names a file, so it does not end in
// "/". An entry may appear once, judged by its root-linked form.
func ValidateWatchedPaths(paths []WatchedPath) error {
	if len(paths) > MaxWatchedPaths {
		return fmt.Errorf("%w: %d paths, at most %d", ErrInvalidWatchedPaths, len(paths), MaxWatchedPaths)
	}
	// Duplicates are keyed by the root-linked form, since /etc/emond.d/ and /private/etc/emond.d/ are one directory.
	seen := make(map[WatchedPath]struct{}, len(paths))
	for i, p := range paths {
		if err := validateWatchedPath(p); err != nil {
			return fmt.Errorf("%w: entry %d (%q): %s", ErrInvalidWatchedPaths, i, p.Path, err.Error())
		}
		key := WatchedPath{Path: rootLinked(p.Path), Match: p.Match}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: entry %d (%q): listed more than once", ErrInvalidWatchedPaths, i, p.Path)
		}
		seen[key] = struct{}{}
	}
	// Measured with the encoder the payload is written with, so JSON escaping (which can grow a byte to six) is counted as sent.
	encoded, _ := json.Marshal(paths)
	if len(encoded) > MaxWatchedPathSetBytes {
		return fmt.Errorf("%w: the set encodes to %d bytes, at most %d", ErrInvalidWatchedPaths, len(encoded), MaxWatchedPathSetBytes)
	}
	return nil
}

func validateWatchedPath(p WatchedPath) error {
	switch {
	case !strings.HasPrefix(p.Path, "/"):
		return errors.New("the path must be absolute")
	case len(privateSpelling(p.Path)) > MaxWatchedPathBytes:
		// The extension also mutes a firmlinked path in its /private spelling, the one the kernel reports, which is the longer.
		return fmt.Errorf("the path is longer than %d bytes in its /private spelling", MaxWatchedPathBytes)
	case strings.ContainsFunc(p.Path, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return errors.New("the path contains an ASCII control character")
	}
	for s := range strings.SplitSeq(strings.TrimSuffix(p.Path[1:], "/"), "/") {
		if s == "" || s == "." || s == ".." {
			return errors.New(`the path has an empty, "." or ".." segment`)
		}
	}
	switch p.Match {
	case WatchedPathLiteral:
		if strings.HasSuffix(p.Path, "/") {
			return errors.New(`a literal names a file, so it must not end in "/"`)
		}
	case WatchedPathPrefix:
		if !strings.HasSuffix(p.Path, "/") {
			return errors.New(`a prefix names a directory, so it must end in "/"`)
		}
		if len(strings.Split(strings.TrimSuffix(rootLinked(p.Path)[1:], "/"), "/")) < 2 {
			return errors.New("a prefix must lie below a top-level directory")
		}
	default:
		return fmt.Errorf("unknown match %q, want %q or %q", p.Match, WatchedPathLiteral, WatchedPathPrefix)
	}
	return nil
}

// privateSpelling returns a path under /etc, /tmp or /var in its /private form, and any other path unchanged. The mapping itself is
// macOSPathAlias's, which detection-config path matching also uses, so the two cannot disagree about which paths are firmlinked.
func privateSpelling(path string) string {
	if alias := macOSPathAlias(path); strings.HasPrefix(alias, "/private/") {
		return alias
	}
	return path
}

// rootLinked returns a path under /private/etc, /private/tmp or /private/var in its root-linked form, and any other path unchanged.
func rootLinked(path string) string {
	if alias := macOSPathAlias(path); alias != "" && !strings.HasPrefix(alias, "/private/") {
		return alias
	}
	return path
}
