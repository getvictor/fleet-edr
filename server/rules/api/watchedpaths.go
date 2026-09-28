package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/catchup"
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
// The extension applies a set only when it is ahead of the last one it accepted, ordered by epoch and then version, because
// commands can reach a host out of order. Epoch is what keeps that ordering true after a database restore sends version backwards:
// the next change is stamped past the restored update time, which is ahead of the host once the database clock is past any epoch
// the restore lost. Application control orders policy_epoch the same way.
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
	// UpdatedByLabel is the display label the REST handler resolves from UpdatedBy at read time: a user's email, a service
	// account's name, or "system". Empty when it could not be resolved, and never stored.
	UpdatedByLabel string `json:"updated_by_label,omitempty"`
	// Defaults are the DefaultWatchedPaths this version of the set was stored with, and so pushed with (issue #1167). Recorded so
	// a server whose build carries a different list knows the hosts do not have it yet; not part of the operator's set, and not on
	// the wire.
	Defaults []WatchedPath `json:"-"`
}

// BuiltInWatchedPaths are the paths the extension watches whatever the set holds, mirroring WatchedPaths.builtIn in the extension.
// The set adds to these and cannot remove them. Reported so the console can say what is always watched; the extension, not this
// list, is what enforces it.
var BuiltInWatchedPaths = []WatchedPath{
	{Path: "/etc/sudoers", Match: WatchedPathLiteral},
	{Path: "/etc/sudoers.d/", Match: WatchedPathPrefix},
}

// DefaultWatchedPaths are pushed to every host on top of the operator's set (issue #1167), because shipped file rules watch them:
// the extension emits a file event only for a path it is told to watch, so a rule for any other path could never fire. They are
// not the operator's to remove, the same as BuiltInWatchedPaths, and differ from those only in being enforced by this server's push
// rather than by the extension, which is what lets a server release add one without an extension release.
//
// Low-traffic system directories only: every write under a watched path is an event on the wire.
//
// Changing this list: servers compare their list with the stored defaults for equality, so two builds with different lists running
// at once (a rolling upgrade) each restore their own on every converge pass until the older one is gone.
var DefaultWatchedPaths = []WatchedPath{
	// Emond event-monitor rules and client registrations: persistence and privilege escalation (T1546.014).
	{Path: "/etc/emond.d/rules/", Match: WatchedPathPrefix},
	{Path: "/private/var/db/emondClients/", Match: WatchedPathPrefix},
	// Startup items, a legacy boot-time persistence location (T1037.005).
	{Path: "/Library/StartupItems/", Match: WatchedPathPrefix},
	// The files sshd reads a user's authorized keys from, in every home (T1098.004). Written when a key is added, which is rare.
	{Path: HomeWatchedPathPrefix + ".ssh/authorized_keys", Match: WatchedPathLiteral},
	{Path: HomeWatchedPathPrefix + ".ssh/authorized_keys2", Match: WatchedPathLiteral},
}

// AlwaysWatchedPaths is every path a host watches whatever the operator's set holds: the extension's built-ins, then this server's
// defaults. What the console reports as always watched, and what the rule loader judges a file rule's reach against.
func AlwaysWatchedPaths() []WatchedPath {
	return append(slices.Clone(BuiltInWatchedPaths), DefaultWatchedPaths...)
}

// PushedWatchedPaths is what a host is sent for set: the defaults the set was stored with, then the operator's paths, dropping an
// operator entry that repeats a default (compared through /private, as ValidateWatchedPaths does).
func PushedWatchedPaths(set WatchedPathSet) []WatchedPath {
	seen := make(map[WatchedPath]struct{}, len(set.Defaults))
	out := make([]WatchedPath, 0, len(set.Defaults)+len(set.Paths))
	for _, p := range set.Defaults {
		seen[WatchedPath{Path: rootLinked(p.Path), Match: p.Match}] = struct{}{}
		out = append(out, p)
	}
	for _, p := range set.Paths {
		if _, dup := seen[WatchedPath{Path: rootLinked(p.Path), Match: p.Match}]; !dup {
			out = append(out, p)
		}
	}
	return out
}

// ReachesWatchedPath reports whether a Sigma TargetFilename condition (modifier "" for equality, or "startswith" or "contains") can
// be met by a path some entry of watched covers, so that a file rule carrying it could ever see an event (issue #1167). The agent
// emits file events for watched paths only, so a condition no watched path can meet is one the rule can never match.
//
// Conservative, since the cost of a wrong yes is a rule that looks like coverage and cannot fire. "endswith" alone reaches nothing,
// because it says nothing about the directory. Paths compare through /private, the way the extension mutes them.
func ReachesWatchedPath(watched []WatchedPath, modifier, value string) bool {
	v := rootLinked(value)
	for _, w := range watched {
		if reaches(w.Match, rootLinked(w.Path), modifier, v) {
			return true
		}
	}
	return false
}

// reaches is ReachesWatchedPath for one entry, p being the watched path and v the condition's value, both through /private.
func reaches(match WatchedPathMatch, p, modifier, v string) bool {
	switch {
	case match == WatchedPathLiteral && modifier == "":
		return p == v
	case match == WatchedPathLiteral && modifier == "startswith":
		return strings.HasPrefix(p, v)
	case match == WatchedPathLiteral && modifier == "contains":
		return strings.Contains(p, v)
	case match == WatchedPathPrefix && modifier == "":
		// A path inside the watched tree.
		return strings.HasPrefix(v, p)
	case match == WatchedPathPrefix && modifier == "startswith":
		// A narrower prefix inside the tree, or a broader one every path in the tree starts with.
		return strings.HasPrefix(v, p) || strings.HasPrefix(p, v)
	case match == WatchedPathPrefix && modifier == "contains":
		// A fragment that begins inside the tree, or one the tree's own path contains.
		return strings.HasPrefix(v, p) || strings.Contains(p, v)
	}
	return false
}

// WatchedPathEnrollment is a host with an active enrollment and when it last enrolled, as the watched-path catch-up reads it. A
// re-enrollment follows a reinstall, which removes the extension's persisted set, so a set queued before it may no longer be on the
// host.
type WatchedPathEnrollment struct {
	HostID     string
	EnrolledAt time.Time
}

// WatchedPathEnrollmentLister returns the hosts with an active enrollment. cmd/main adapts the endpoint context's enrollment list.
type WatchedPathEnrollmentLister func(ctx context.Context) ([]WatchedPathEnrollment, error)

// WatchedPathCommand is what the watched-path catch-up needs to know about a host's latest set_watched_paths command.
type WatchedPathCommand struct {
	Payload []byte
	// Status is already the shared catch-up vocabulary, mapped by the context that owns the command lifecycle rather than cast from
	// its spelling here (issue #1071). A cast would make a rename there an unrecognized status here, which the catch-up leaves
	// alone, silently stopping the sweep for every host holding one.
	Status    catchup.Status
	CreatedAt time.Time
	// CompletedAt is when the command reached a terminal status, and zero while it has not.
	CompletedAt time.Time
}

// WatchedPathCommandLister returns, per host, its most recently queued command of a type. cmd/main adapts the response context's
// LatestOfType.
type WatchedPathCommandLister func(ctx context.Context, commandType string, hostIDs []string) (map[string]WatchedPathCommand, error)

// MaxWatchedPaths bounds the set. Every entry is a mute the file-tamper client holds, two for a path under a firmlinked root, and a
// set this size already covers the uses the issue names (canaries, credential stores, a handful of integrity-monitored directories)
// many times over.
const MaxWatchedPaths = 32

// HomeWatchedPathPrefix starts a watched path that names a path in every user's home, as `~/.ssh/authorized_keys` does (issue
// #1167). Endpoint Security mutes only literal paths and prefixes, so each host's extension expands such an entry into one path per
// home: root's and each person's account, re-read every few minutes so an account added later is covered. An extension that
// predates it skips the entry and watches the rest of the set.
const HomeWatchedPathPrefix = "~/"

// MaxWatchedPathBytes bounds one path: the macOS PATH_MAX of 1024 counts the terminating NUL of the C string es_mute_path takes, so the
// longest path it can mute is one byte shorter.
const MaxWatchedPathBytes = 1023

// MaxOperatorWatchedPathSetBytes bounds the operator's paths as the server encodes them. The bound predates the default paths and
// still measures the operator's paths alone, so a set accepted before the defaults existed still validates and can always gain them.
// Real watched paths are short; the bound only bites on a set of many maximum-length paths, which MaxWatchedPaths and
// MaxWatchedPathBytes alone would allow at over 30 KiB.
const MaxOperatorWatchedPathSetBytes = 8 * 1024

// defaultWatchedPathsAllowance is the room MaxWatchedPathSetBytes leaves for DefaultWatchedPaths, which a test holds to it.
const defaultWatchedPathsAllowance = 512

// MaxWatchedPathSetBytes bounds what a host is sent: the defaults followed by the operator's paths. The fan-out repeats that payload
// on every row of a batched insert of up to 256 hosts, so this keeps one statement near 2 MiB, inside the 4 MiB max_allowed_packet
// the server is designed to work under.
const MaxWatchedPathSetBytes = MaxOperatorWatchedPathSetBytes + defaultWatchedPathsAllowance

// ErrInvalidWatchedPaths is returned for a set the server refuses. The wrapped message names the entry and the reason, and the REST
// handler returns it to the operator.
var ErrInvalidWatchedPaths = errors.New("invalid watched paths")

// ValidateWatchedPaths checks a proposed set. It is the one place the set is validated: the agent checks only the envelope and the
// extension applies what it is given.
//
// A path must be absolute, or start with HomeWatchedPathPrefix to name a path in every user's home, which is then judged as the
// path it would be in a home at the root. It must be clean (no empty, "." or ".." segment), within MaxWatchedPathBytes in its
// /private spelling (the one the extension mutes and the kernel reports for /etc, /tmp and /var), and free of ASCII control
// characters (NUL included, which would truncate the path the kernel receives). A prefix names a directory, so it ends in "/", and
// it must lie below a top-level directory: a prefix such as "/Users/" or "/Library/" would put every write under that tree on the
// wire, which is the firehose ADR-0008 removed. A literal names a file, so it does not end in "/". An entry may appear once, judged
// by its root-linked form.
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
	if len(encoded) > MaxOperatorWatchedPathSetBytes {
		return fmt.Errorf("%w: the set encodes to %d bytes, at most %d", ErrInvalidWatchedPaths, len(encoded), MaxOperatorWatchedPathSetBytes)
	}
	return nil
}

func validateWatchedPath(p WatchedPath) error {
	if rest, ok := strings.CutPrefix(p.Path, HomeWatchedPathPrefix); ok {
		// Judged as the path it would be in a home at the top of the filesystem, so every rule below applies, and a prefix's
		// depth is counted below the home: `~/Library/` would put every write in every user's Library on the wire.
		if rest == "" {
			return errors.New("a path in every home must name something inside the home")
		}
		return validateWatchedPath(WatchedPath{Path: "/" + rest, Match: p.Match})
	}
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
