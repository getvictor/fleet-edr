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

// ErrRefused reports that a proposed change was rejected by validation and was NOT written.
//
// A CHANGE rather than a document, because a deletion is refused through this too: what validation judges is the corpus a write
// would produce, and removing a rule can be the change that breaks one. Naming a document here would make the message read as
// nonsense for the delete path, which review caught.
//
// Wrapped around the validator's own reason rather than replacing it: the reason is what tells an operator which field to fix, and
// re-phrasing it here would make this package a second, drifting account of why the loader refuses things.
var ErrRefused = errors.New("rule content: change refused")

// ErrCorpusChanged reports that the corpus moved between being validated and being written, so the write was refused.
//
// This is what makes validation mean anything under concurrency. Validating a snapshot and then writing in a separate transaction
// is a check-then-act: two operators adding `authored/x.yml` and `other/x.yml` at the same time each validate against a corpus
// without the other, both pass, and the corpus that lands claims one rule identity twice. Every replica then refuses the whole
// thing and falls back to the copy embedded in its binary, which is precisely the failure whole-corpus validation exists to
// prevent, reintroduced through the back door.
//
// The caller's remedy is to re-read, re-validate and retry, which is why this is a distinct error rather than a generic conflict.
var ErrCorpusChanged = errors.New("rule content: corpus changed since it was validated")

// Writer is the write surface for rule content, the counterpart to Corpus.
//
// Per-document rather than whole-corpus, which is the difference between this and Replace. An operator edits ONE rule; expressing
// that as "read the corpus, change one entry, write it all back" makes every edit a read-modify-write over the whole corpus, and
// two operators editing different rules would silently discard each other's work.
//
// Every method returns the corpus version the write produced, so a caller can report what a replica has to reach before the change
// is live without a second round trip to read it.
// Every method takes the corpus version the caller validated against and refuses with ErrCorpusChanged if the corpus has moved
// since. Without that the validation above is advisory: it describes a corpus that no longer exists by the time the write lands.
type Writer interface {
	// PutDocument creates or replaces the document at doc.Path and returns the new corpus version.
	PutDocument(ctx context.Context, doc Document, expectedVersion int64) (int64, error)
	// DeleteDocument removes the document at path and returns the new corpus version. Reports ErrDocumentNotFound, and leaves the
	// corpus version unmoved, when there was nothing there.
	DeleteDocument(ctx context.Context, path string, expectedVersion int64) (int64, error)
}

// Validator decides whether a proposed corpus may replace the one in force.
//
// It takes the whole document SET rather than the one document being written, and that is the correction that matters here. A
// rule's identity comes from its file stem, and the loader treats two documents claiming one identity as an error that refuses
// the entire corpus, not as a per-document rejection. So a document that is perfectly valid alone can still be the thing that
// takes a deployment's whole rule set down to the corpus embedded in its binary. Validating it alone would accept exactly that.
//
// Whole-set validation also makes the promise honest: "accepted" means "this deployment will load this", which is the only
// definition of valid worth enforcing at a trust boundary.
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
	// Validate reports whether docs would load as a corpus. A non-nil error means refused, and its message is shown to the
	// operator. Warnings are advisory: a corpus with warnings is still written.
	Validate(ctx context.Context, docs []Document) (warnings []string, err error)
}
