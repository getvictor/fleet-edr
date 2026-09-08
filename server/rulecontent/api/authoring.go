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

// PackLifecycle is the pack half of rule content: which generation of shipped rules a deployment runs, and restoring the one
// before it.
//
// Declared here and implemented by rulecontent's bootstrap, for the reason Author is: the operator surface lives in the rules
// context, which must be able to call this without rulecontent depending on it (ADR-0021). Reading the build's own pack is the
// implementation's business, not the caller's, which is why neither method takes one.
type PackLifecycle interface {
	// Status reports the generation installed, the generation this build carries, and which rules differ.
	Status(ctx context.Context) (PackStatus, error)
	// Rollback restores the generation the last install replaced, and records that the current one was declined.
	Rollback(ctx context.Context, mkAudit PackAuditEntryFunc) (PackRollback, error)
}

// AuditOutboxEntry is the caller's audit row, carried into the same transaction as the content change so the two commit together
// or not at all (issue #886).
//
// Opaque on purpose, and that is the whole design. The audit store sits behind an interface the identity context owns, so a
// rules-context service cannot enlist it in this context's transaction (ADR-0021), and this context must not learn what an audit
// event is in order to store one. So it carries bytes it does not interpret: the caller encodes, the caller decodes, and the only
// thing this context promises is that they commit with the change.
//
// A zero value means "record nothing", which is what an internal caller with no actor passes. The seeding and upgrade paths are
// exactly that: they are the product installing its own content, not an operator changing it, and they have no reason and no actor
// to record.
type AuditOutboxEntry struct {
	// Kind names the ENCODING so a drain meeting an entry from a newer version can leave it rather than mis-decode it. Not the
	// audit action, which lives inside Payload where the caller put it.
	Kind string
	// Payload is the encoded audit event. Must be valid JSON when Kind is set, because the column is JSON.
	Payload []byte
}

// Zero reports whether the entry asks for nothing to be recorded.
func (e AuditOutboxEntry) Zero() bool { return e.Kind == "" && len(e.Payload) == 0 }

// AuditEntryFunc builds the entry for a document change, given the facts only this context knows at the time.
//
// A builder rather than a value because those facts are computed HERE: the version a change will produce is the base the write is
// validated against plus one, and the warnings are narrowed to the document under change by the corpus-wide validation. A caller
// one layer up cannot supply either without duplicating this context's logic, and an audit row that omitted them would be a
// weaker trail than the one this replaces.
//
// The function is the caller's and the bytes it returns are opaque here, so the boundary is unchanged: this context invokes what
// it was given and stores the result, and still does not know what an audit event is (ADR-0021).
//
// Nil means record nothing, which is the internal callers: seeding and the pack upgrade are the product installing its own
// content rather than an operator changing it. An error from the builder fails the change, which is correct: an audit row that
// cannot be built is a change that must not happen silently.
type AuditEntryFunc func(version int64, warnings []ContentWarning) (AuditOutboxEntry, error)

// PackAuditEntryFunc is AuditEntryFunc for a rollback, whose recordable facts are the restored generation and what it withheld.
type PackAuditEntryFunc func(rollback PackRollback) (AuditOutboxEntry, error)

// BuildAuditEntry invokes f when it is set, and reports the zero entry when it is not.
func BuildAuditEntry(f AuditEntryFunc, version int64, warnings []ContentWarning) (AuditOutboxEntry, error) {
	if f == nil {
		return AuditOutboxEntry{}, nil
	}
	return f(version, warnings)
}

// PendingAuditEntry is one undelivered outbox row, as the drain sees it.
type PendingAuditEntry struct {
	ID      int64
	Kind    string
	Payload []byte
}

// AuditOutbox is the drain surface: read the oldest undelivered entries, and delete the ones that were delivered.
//
// Declared here and implemented by rulecontent's store, for the same reason the lifecycles are: the drain lives in the rules
// context, beside the recorder it delivers to.
type AuditOutbox interface {
	// PendingAuditEntries returns up to limit undelivered entries, oldest first, so audit rows land in the order the changes did.
	PendingAuditEntries(ctx context.Context, limit int) ([]PendingAuditEntry, error)
	// DeleteAuditEntries removes entries that were delivered. Deleting is what marks delivery, so it runs after the recorder
	// reports success and never before.
	DeleteAuditEntries(ctx context.Context, ids []int64) error
}

// ErrNoPreviousPack reports that no earlier generation of shipped content is retained, so there is nothing to roll back to.
//
// The ordinary state of a deployment that has never upgraded: it seeded once and is still running what it seeded. Reported rather
// than treated as an empty restore, which would leave the deployment detecting nothing.
var ErrNoPreviousPack = errors.New("rule content: no previous rule pack is retained")

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
	PutDocument(ctx context.Context, doc Document, expectedVersion int64, audit AuditOutboxEntry) (int64, error)
	// DeleteDocument removes the document at path and returns the new corpus version. Reports ErrDocumentNotFound, and leaves the
	// corpus version unmoved, when there was nothing there.
	DeleteDocument(ctx context.Context, path string, expectedVersion int64, audit AuditOutboxEntry) (int64, error)
}

// ContentWarning is one advisory finding about ONE document.
//
// Carrying the path is what makes the warning attributable, and its absence was a real defect (#876). Validation is corpus-wide
// by design, so a validator handed a proposed corpus reports findings about every document in it, including the ones the operator
// did not touch. With warnings as bare strings a caller could not tell those apart without matching on message text, so an
// operator writing one rule was told about unrelated files, and worse, the audit row for their change recorded findings about
// documents they never edited.
//
// A reviewer reading an audit row has to be able to trust that what it says is about the change it names. That is the whole
// reason this is a struct rather than a string.
type ContentWarning struct {
	// Path is the document the finding is about, as stored.
	Path string
	// Message is what to tell the operator, in the words of whatever decided it.
	Message string
}

// WarningsFor returns the warnings about one document, dropping findings about every other.
//
// Lives here rather than in each caller because "which warnings belong to this change" is a property of the contract, not a
// judgement each consumer should make differently.
func WarningsFor(warnings []ContentWarning, path string) []ContentWarning {
	var out []ContentWarning
	for _, w := range warnings {
		if w.Path == path {
			out = append(out, w)
		}
	}
	return out
}

// WarningMessages flattens warnings to their messages, for a caller that has already decided which ones it is reporting.
func WarningMessages(warnings []ContentWarning) []string {
	out := make([]string, 0, len(warnings))
	for _, w := range warnings {
		out = append(out, w.Message)
	}
	return out
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
	//
	// Warnings cover the WHOLE proposed corpus, because that is what was validated, and each carries the document it is about so
	// a caller can report the ones concerning the change it is making.
	Validate(ctx context.Context, docs []Document) (warnings []ContentWarning, err error)
}

// Author is the authoring lifecycle: validate a proposed change, then apply it.
//
// The published counterpart to Writer, and the difference between them is the whole point. Writer is the raw store operation and
// makes no promise about validity; Author is the surface a caller outside this context should hold, because going through it is
// what guarantees the corpus that lands is one the deployment can load.
//
// Both return the new corpus version and any advisory warnings. A warning does NOT mean the change was refused: a rule this
// deployment cannot run is still a rule an operator may legitimately store, so it is reported rather than rejected.
//
// Errors a caller is expected to branch on: ErrRefused when validation rejected the proposed corpus, ErrDocumentNotFound when a
// delete named a path that holds nothing, and ErrCorpusChanged when the corpus moved between validation and the write, which the
// caller resolves by retrying rather than by reporting a failure.
type Author interface {
	// Put creates or replaces the document at doc.Path. Warnings are about that document only.
	Put(ctx context.Context, doc Document, mkAudit AuditEntryFunc) (version int64, warnings []ContentWarning, err error)
	// Delete removes the document at path. Warnings are about that document only, which in practice means none: a document that
	// is gone has nothing left to warn about.
	Delete(ctx context.Context, path string, mkAudit AuditEntryFunc) (version int64, warnings []ContentWarning, err error)
}
