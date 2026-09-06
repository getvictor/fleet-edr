package api

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"testing/fstest"
)

// Document is one rule-content file: the path the corpus loader reads it under, and its bytes.
//
// Path rather than an opaque id because the loader's behaviour is path-dependent in ways that are contractual, not incidental: it
// selects files by extension, and it derives a rule's identity from the file's stem, which is how duplicate-stem collisions are
// detected before anything is parsed.
type Document struct {
	Path    string
	Content []byte
	// Source is where this document came from, and it is always populated on a document READ back.
	//
	// On the way IN it depends on WHICH WRITE SURFACE the document arrived through, never on the document's own path. The
	// distinction is contractual: deriving provenance from a path is the specific thing this design rules out, since an operator
	// chooses their own paths and could then launder an authored rule into a vendored one.
	//
	// Through the AUTHORING surface this field is ignored: that write records the operator's provenance itself, because how a
	// document arrived is an observation rather than a claim the caller gets to make. A whole-corpus replacement may state it,
	// and must be able to, since that is the surface a pack upgrade and a restore go through and both have to put an operator's
	// own rules back as theirs rather than relabelling them. Empty there means "not stated", which is recorded as vendored.
	Source Source
}

// Corpus is the read surface `rules` consumes to build its evaluatable rule set.
//
// Version is separated from Documents deliberately, and the split is the point rather than a convenience: a replica converges by
// polling for change, and polling a single-row counter is cheap enough to do on an interval where re-reading every document is
// not. This mirrors how detectionconfig's refresh avoids loading a snapshot it does not need.
type Corpus interface {
	// Documents returns every document in the active corpus, in a stable order.
	Documents(ctx context.Context) ([]Document, error)
	// Version returns the corpus version. Changes whenever the documents change, and is cheap enough to poll.
	Version(ctx context.Context) (int64, error)
}

// FS presents documents as an fs.FS, so a consumer can hand them to a loader that reads files.
//
// This exists so the corpus can be stored without rewriting how it is parsed. The Sigma loader already takes an fs.FS and derives
// rule identity from file stems, including the duplicate-stem check that runs before any parsing; reimplementing that against a
// document slice would be a second parser to keep in step with the first, which is the failure mode this codebase is most prone to.
//
// fstest.MapFS is the implementation rather than a hand-rolled one, and the objection to that is worth answering here because the
// package name invites it. testing/fstest does NOT depend on testing: its own imports are errors, fmt, io, io/fs, maps, path,
// slices, strings, testing/iotest and time. So this links no test framework and registers no flags; MapFS is an ordinary fs.FS
// over a map whose semantics are specified.
//
// Hand-rolling it would also be worse than it sounds. The loader reaches this through fs.WalkDir, so the implementation has to
// synthesize the parent directories that a flat document set does not contain, which MapFS already does correctly. A local copy
// would be fiddly code, exercised only here, in service of avoiding a package name.
func FS(docs []Document) fs.FS {
	mapped := make(fstest.MapFS, len(docs))
	for _, d := range docs {
		mapped[strings.TrimPrefix(d.Path, "/")] = &fstest.MapFile{Data: d.Content}
	}
	return mapped
}

// SortDocuments orders documents by path, so a corpus loads in the same order on every replica.
//
// Load order is observable: registration order is what the operator-facing catalog and the generated rule reference are listed in,
// and a rule set that differs by replica would make those two surfaces disagree depending on which replica answered.
func SortDocuments(docs []Document) {
	sort.Slice(docs, func(i, j int) bool { return docs[i].Path < docs[j].Path })
}

// PackInstall is what installing a build's rule pack did.
//
// Skipped is reported rather than logged and forgotten because it is a real divergence: the deployment is not running a rule the
// pack ships, and the reason is the operator's own rule of the same identity. That is the correct outcome and still something they
// are entitled to see, since nothing else would tell them.
type PackInstall struct {
	Changed bool
	Version int64
	Skipped []string
}

// RuleIdentity maps a document's path to the identity the rule it holds will load under.
//
// Supplied by the caller rather than derived here, for the reason the provenance projection is: the derivation belongs to the
// loader, and a second copy of it in this context would agree until one of them changed. Then the copies would disagree silently,
// which for this particular question means installing a pack document that collides with an operator's rule.
//
// It matters that this is identity and not path. A rule is identified by its file STEM (#873), so `authored/foo.yml` and
// `imported/foo.yml` are the SAME rule stored twice, and a corpus holding both does not load at all: the loader refuses the whole
// set rather than choosing between them, so every rule on the deployment stops, not just the pair.
type RuleIdentity func(path string) string

// Identify answers safely for a nil RuleIdentity, for which a document's identity is its path. That is the weakest correct
// answer rather than a convenient one: it still catches a pack document landing on the exact path an operator holds, and it is
// what a caller with no loader of its own can honestly claim to know.
func (r RuleIdentity) Identify(path string) string {
	if r == nil {
		return path
	}
	return r(path)
}

// Source says where a rule document came from: shipped with the product, or written by an operator.
//
// Recorded when the document is stored rather than derived from its path, which is the decision the rest of this rests on. A
// rule's identity is its file STEM and not its path (#873), and the load walks the whole stored set precisely so authored content
// need not live under a directory named `imported`. Reading provenance off a prefix would contradict that AND be chosen by the
// operator it describes: writing to `imported/mine.yml` would launder an authored rule into a vendored one, and with it a licence
// attribution it was never under.
type Source string

const (
	// SourceVendored marks content shipped with the product. It carries the upstream project's licence, and its attribution is
	// how that licence is honoured.
	SourceVendored Source = "vendored"
	// SourceAuthored marks content an operator wrote. It is theirs, carries no upstream licence, and must not be credited to an
	// upstream project.
	SourceAuthored Source = "authored"
)

// Valid reports whether s is a source this system records. Anything else is a row written by a version that knew something this
// one does not, which a reader must not silently treat as either known value.
func (s Source) Valid() bool {
	return s == SourceVendored || s == SourceAuthored
}

// ErrUnknownSource reports a provenance value this version does not recognise, on the way in or on the way out.
//
// Refusing is the only safe direction, and the asymmetry is why. An unrecognised value is not SourceAuthored, so attribution
// treats it as vendored and credits the upstream project; it is also not SourceVendored, so the pack digest excludes it. One
// unknown row would therefore be credited to SigmaHQ while being left out of the identity of the pack it is claimed to belong to.
// The first half is a licence claim about content nobody here can vouch for, which is the failure this whole change exists to
// prevent, so a corpus carrying one is refused rather than half-interpreted.
var ErrUnknownSource = errors.New("rule content: unknown document source")
