// Package mysql is the rulecontent context's persistence for rule content: the corpus documents and the version counter a replica
// polls to notice another replica's change.
package mysql

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/rulecontent/api"
)

// Store persists rule content. Satisfies api.Corpus.
type Store struct {
	db *sqlx.DB
}

// New builds a Store over an existing handle.
func New(db *sqlx.DB) *Store { return &Store{db: db} }

// Documents returns every document in the corpus, ordered by path so every replica loads the same corpus in the same order.
func (s *Store) Documents(ctx context.Context) ([]api.Document, error) {
	var rows []struct {
		Path    string `db:"path"`
		Content string `db:"content"`
	}
	if err := s.db.SelectContext(ctx, &rows, "SELECT path, content FROM rule_corpus_documents ORDER BY path"); err != nil {
		return nil, fmt.Errorf("select rule corpus documents: %w", err)
	}
	docs := make([]api.Document, 0, len(rows))
	for _, r := range rows {
		docs = append(docs, api.Document{Path: r.Path, Content: []byte(r.Content)})
	}
	return docs, nil
}

// Version returns the corpus version counter.
//
// A single indexed row, so this is what a replica's refresh polls: re-reading every document on an interval to discover that
// nothing changed is the cost this exists to avoid.
func (s *Store) Version(ctx context.Context) (int64, error) {
	var version int64
	if err := s.db.GetContext(ctx, &version, "SELECT version FROM rule_corpus_meta WHERE id = 1"); err != nil {
		return 0, fmt.Errorf("select rule corpus version: %w", err)
	}
	return version, nil
}

// Replace writes docs as the entire corpus and bumps the version, in one transaction.
//
// Whole-corpus replacement rather than per-document upserts, because a corpus is the unit that is valid or not: a rule removed
// upstream has to disappear, and a partially applied corpus is a state no reader should be able to observe. The version bump is
// inside the transaction for the same reason, so a replica that sees the new version can only ever read the documents that go
// with it, and it happens FIRST so that every mutation locks meta before documents (see replaceWithin).
//
// Returns the new version.
func (s *Store) Replace(ctx context.Context, docs []api.Document) (int64, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx for corpus replace: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	version, err := replaceWithin(ctx, tx, docs)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit corpus replace: %w", err)
	}
	return version, nil
}

// replaceWithin performs the whole-corpus write inside an open transaction and returns the new version. Shared by Replace and
// ReplaceIfEmpty so the two cannot drift on what "replace" means.
//
// The meta row is written FIRST, before any document, and the order is the point rather than an accident. Every mutation of this
// corpus therefore takes its locks as meta-then-documents. When the version bump came last, Replace held document locks while
// waiting for meta and ReplaceIfEmpty held meta while waiting for documents, which is an ABBA deadlock between an operator's
// replacement and a startup seed: two paths that exist precisely to run at the same time.
//
// Fixing the ORDER rather than retrying the deadlock, because a retry would paper over a cycle this code creates itself. The
// deadlock retry that other stores here use is for contention this code does not control.
func replaceWithin(ctx context.Context, tx *sqlx.Tx, docs []api.Document) (int64, error) {
	if _, err := tx.ExecContext(ctx, "UPDATE rule_corpus_meta SET version = version + 1 WHERE id = 1"); err != nil {
		return 0, fmt.Errorf("bump rule corpus version: %w", err)
	}
	var version int64
	if err := tx.GetContext(ctx, &version, "SELECT version FROM rule_corpus_meta WHERE id = 1"); err != nil {
		return 0, fmt.Errorf("read rule corpus version: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM rule_corpus_documents"); err != nil {
		return 0, fmt.Errorf("clear rule corpus: %w", err)
	}
	for _, d := range docs {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO rule_corpus_documents (path, content) VALUES (?, ?)", d.Path, string(d.Content)); err != nil {
			return 0, fmt.Errorf("insert rule corpus document %q: %w", d.Path, err)
		}
	}
	return version, nil
}

// IsEmpty reports whether the corpus holds no documents.
func (s *Store) IsEmpty(ctx context.Context) (bool, error) {
	var count int64
	if err := s.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM rule_corpus_documents"); err != nil {
		return false, fmt.Errorf("count rule corpus documents: %w", err)
	}
	return count == 0, nil
}

// ReplaceIfEmpty writes docs as the corpus only if the corpus is currently empty, and reports whether it wrote.
//
// The check and the write are ONE transaction, which is the whole point of the method existing rather than the caller doing
// IsEmpty followed by Replace. Separately they are a check-then-act: content committed between them is deleted, so a replica that
// read "empty" and then wrote would discard a rule authored in that window. The window is narrow at startup and the consequence
// is losing an operator's content, which is not a trade worth taking for one fewer method.
//
// The meta row is locked first, and locking THAT row rather than the documents is deliberate: an empty table has no rows for
// SELECT ... FOR UPDATE to lock, so a concurrent seeder would not be serialized by locking what is not there. The counter row
// always exists, so it acts as the mutex every seeder passes through.
func (s *Store) ReplaceIfEmpty(ctx context.Context, docs []api.Document) (bool, int64, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return false, 0, fmt.Errorf("begin tx for conditional corpus replace: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var locked int64
	if err := tx.GetContext(ctx, &locked, "SELECT version FROM rule_corpus_meta WHERE id = 1 FOR UPDATE"); err != nil {
		return false, 0, fmt.Errorf("lock rule corpus meta: %w", err)
	}
	var count int64
	if err := tx.GetContext(ctx, &count, "SELECT COUNT(*) FROM rule_corpus_documents"); err != nil {
		return false, 0, fmt.Errorf("count rule corpus documents: %w", err)
	}
	if count > 0 {
		return false, locked, nil
	}

	version, err := replaceWithin(ctx, tx, docs)
	if err != nil {
		return false, 0, err
	}
	if err := tx.Commit(); err != nil {
		return false, 0, fmt.Errorf("commit conditional corpus replace: %w", err)
	}
	return true, version, nil
}
