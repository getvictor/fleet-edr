package api

import (
	"context"
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
