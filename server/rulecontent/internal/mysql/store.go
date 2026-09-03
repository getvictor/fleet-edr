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
// with it.
//
// Returns the new version.
func (s *Store) Replace(ctx context.Context, docs []api.Document) (int64, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx for corpus replace: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, "DELETE FROM rule_corpus_documents"); err != nil {
		return 0, fmt.Errorf("clear rule corpus: %w", err)
	}
	for _, d := range docs {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO rule_corpus_documents (path, content) VALUES (?, ?)", d.Path, string(d.Content)); err != nil {
			return 0, fmt.Errorf("insert rule corpus document %q: %w", d.Path, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE rule_corpus_meta SET version = version + 1 WHERE id = 1"); err != nil {
		return 0, fmt.Errorf("bump rule corpus version: %w", err)
	}
	var version int64
	if err := tx.GetContext(ctx, &version, "SELECT version FROM rule_corpus_meta WHERE id = 1"); err != nil {
		return 0, fmt.Errorf("read rule corpus version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit corpus replace: %w", err)
	}
	return version, nil
}

// IsEmpty reports whether the corpus holds no documents, which is how the seed decides whether to run.
func (s *Store) IsEmpty(ctx context.Context) (bool, error) {
	var count int64
	if err := s.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM rule_corpus_documents"); err != nil {
		return false, fmt.Errorf("count rule corpus documents: %w", err)
	}
	return count == 0, nil
}
