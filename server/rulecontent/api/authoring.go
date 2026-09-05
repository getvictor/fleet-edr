package api

import (
	"context"
	"errors"
)

// ErrDocumentNotFound reports that the corpus has no document at the path a caller named.
//
// Returned by Writer.DeleteDocument rather than swallowed, because a delete that silently succeeds on a path that was never there
// tells an operator they removed a rule when they removed nothing. The distinction matters most in exactly the case where it is
// easiest to get wrong: a typo in a path deletes nothing and, without this, reports success.
var ErrDocumentNotFound = errors.New("rule content: document not found")

// ErrRefused reports that a submitted document was rejected by validation and was NOT written.
//
// Wrapped around the validator's own reason rather than replacing it: the reason is what tells an operator which field to fix, and
// re-phrasing it here would make this package a second, drifting account of why the loader refuses things.
var ErrRefused = errors.New("rule content: document refused")

// Writer is the write surface for rule content, the counterpart to Corpus.
//
// Per-document rather than whole-corpus, which is the difference between this and Replace. An operator edits ONE rule; expressing
// that as "read the corpus, change one entry, write it all back" makes every edit a read-modify-write over the whole corpus, and
// two operators editing different rules would silently discard each other's work.
//
// Every method returns the corpus version the write produced, so a caller can report what a replica has to reach before the change
// is live without a second round trip to read it.
type Writer interface {
	// PutDocument creates or replaces the document at doc.Path and returns the new corpus version.
	PutDocument(ctx context.Context, doc Document) (int64, error)
	// DeleteDocument removes the document at path and returns the new corpus version. Reports ErrDocumentNotFound, and leaves the
	// corpus version unmoved, when there was nothing there.
	DeleteDocument(ctx context.Context, path string) (int64, error)
}

// Validator decides whether a submitted document may join the corpus.
//
// Declared HERE, in the content context, and implemented elsewhere: this is the inversion that lets rule content own its authoring
// lifecycle without importing the evaluator. ADR-0021 gives `rulecontent` the validation of untrusted rule content, but the only
// honest validator is the corpus loader itself, which lives in `rules` because it produces evaluatable rules. Declaring the port
// here and letting `rules` supply it keeps `rulecontent` importing no other context's api, which is what arch-go.yml checks.
//
// The alternative, re-implementing the loader's checks in this package, would create a second notion of validity whose only job is
// to agree with the first. It would drift, and the direction it drifts is the dangerous one: content this package accepts and the
// deployment then refuses to load.
type Validator interface {
	// Validate reports whether doc may join the corpus. A non-nil error means refused, and its message is shown to the operator.
	// Warnings are advisory: a document with warnings is still written.
	Validate(ctx context.Context, doc Document) (warnings []string, err error)
}
