// Package authoring is the rulecontent context's write lifecycle: validate a proposed corpus, then store it.
//
// It exists as its own package rather than as methods on the store because the ORDER is the invariant. Storing content that the
// deployment cannot load is the failure this whole phase is built to prevent, and a store that also validates would let a future
// caller reach the write without the check by picking the other method.
package authoring

import (
	"context"
	"errors"
	"fmt"

	"github.com/fleetdm/edr/server/rulecontent/api"
)

// Compile-time proof that the service satisfies the published lifecycle. Without it the two drift apart until the wiring in
// cmd/main fails to build, which is a long way from where the mistake would be.
var _ api.Author = (*Service)(nil)

// Service validates and applies single-document changes to the corpus.
type Service struct {
	corpus    api.Corpus
	writer    api.Writer
	validator api.Validator
}

// New builds a Service. Every dependency is required: a Service that could be constructed without a validator would make
// "validated" a property of the wiring rather than of the type, and the wiring is exactly what a future caller gets wrong.
func New(corpus api.Corpus, writer api.Writer, validator api.Validator) (*Service, error) {
	if corpus == nil || writer == nil || validator == nil {
		return nil, errors.New("rule content authoring: corpus, writer and validator are all required")
	}
	return &Service{corpus: corpus, writer: writer, validator: validator}, nil
}

// Put validates the corpus that writing doc would produce, and writes it if that corpus loads.
//
// Returns the new corpus version and any advisory warnings. A refusal comes back wrapped in api.ErrRefused with the validator's
// own reason, and nothing is written.
func (s *Service) Put(ctx context.Context, doc api.Document) (int64, []api.ContentWarning, error) {
	proposed, base, err := s.proposed(ctx, func(docs []api.Document) []api.Document {
		return upsert(docs, doc)
	})
	if err != nil {
		return 0, nil, err
	}
	all, err := s.validator.Validate(ctx, proposed)
	// Narrowed to the document being written. Validation is corpus-wide, so `all` describes every document in the proposed set
	// including the ones this change did not touch; reporting those would tell an operator about files they cannot fix and, since
	// the caller records warnings on the audit row, would attribute them to a change they are not about (#876).
	//
	// The corpus-wide findings are not lost, they are simply not this change's. Somewhere reporting corpus health is where they
	// belong.
	warnings := api.WarningsFor(all, doc.Path)
	if err != nil {
		return 0, warnings, fmt.Errorf("%w: %w", api.ErrRefused, err)
	}
	version, err := s.writer.PutDocument(ctx, doc, base)
	if err != nil {
		return 0, warnings, err
	}
	return version, warnings, nil
}

// Delete validates the corpus that removing path would produce, and removes it if that corpus loads.
//
// Deleting is validated for the same reason writing is, which is less obvious and worth stating: removing a rule can be the thing
// that breaks a corpus, because what remains still has to load. Reporting api.ErrDocumentNotFound when the path holds nothing
// comes from the writer, so a delete of something absent is refused before it can move the version.
func (s *Service) Delete(ctx context.Context, path string) (int64, []api.ContentWarning, error) {
	var found bool
	proposed, base, err := s.proposed(ctx, func(docs []api.Document) []api.Document {
		kept := make([]api.Document, 0, len(docs))
		for _, d := range docs {
			if d.Path == path {
				found = true
				continue
			}
			kept = append(kept, d)
		}
		return kept
	})
	if err != nil {
		return 0, nil, err
	}
	if !found {
		// Reported here rather than left to the writer so the validator is not asked about a corpus nobody proposed. Same error
		// the writer would return, so a caller branches on one thing either way.
		return 0, nil, fmt.Errorf("%w: %s", api.ErrDocumentNotFound, path)
	}
	all, err := s.validator.Validate(ctx, proposed)
	// Narrowed the same way, which for a delete means empty: the proposed corpus no longer contains this path, so nothing in the
	// findings is about it. That is the correct answer rather than a degenerate one. A deletion that BREAKS the corpus is an
	// error, not a warning, and comes back through err below.
	warnings := api.WarningsFor(all, path)
	if err != nil {
		return 0, warnings, fmt.Errorf("%w: %w", api.ErrRefused, err)
	}
	version, err := s.writer.DeleteDocument(ctx, path, base)
	if err != nil {
		return 0, warnings, err
	}
	return version, warnings, nil
}

// proposed reads the corpus in force and applies change to a copy of it, returning what to validate and the version it was built
// from.
//
// A copy, because the validator must see the corpus the write WOULD produce rather than the one that exists. Validating the
// submitted document alone would miss the failure that matters most here: rule identity is a file stem, and two documents claiming
// one identity refuse the entire corpus rather than one document, so a document that is valid alone can still be the write that
// drops a deployment to the rule set embedded in its binary.
//
// The VERSION is read BEFORE the documents, and the order is deliberate rather than incidental. A write landing between the two
// reads then leaves us holding a version older than the documents we read, so the write is refused with ErrCorpusChanged and the
// caller retries: a false negative, which is free. Reading them the other way round would leave us holding a version NEWER than
// the documents, and the write would be accepted on the strength of a corpus we never actually saw.
func (s *Service) proposed(
	ctx context.Context, change func([]api.Document) []api.Document,
) (docs []api.Document, baseVersion int64, err error) {
	baseVersion, err = s.corpus.Version(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read corpus version: %w", err)
	}
	current, err := s.corpus.Documents(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read corpus in force: %w", err)
	}
	next := change(current)
	api.SortDocuments(next)
	return next, baseVersion, nil
}

// upsert replaces the document at doc.Path, or appends it when the corpus does not have that path yet.
func upsert(docs []api.Document, doc api.Document) []api.Document {
	next := make([]api.Document, 0, len(docs)+1)
	replaced := false
	for _, d := range docs {
		if d.Path == doc.Path {
			next = append(next, doc)
			replaced = true
			continue
		}
		next = append(next, d)
	}
	if !replaced {
		next = append(next, doc)
	}
	return next
}
