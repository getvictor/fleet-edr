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
// No production caller yet: the seed goes through ReplaceIfEmpty, and the surface that replaces a corpus deliberately is the
// operator authoring work (issue #767). It is kept rather than inlined because it is the primitive ReplaceIfEmpty is built from,
// so the two cannot disagree about what replacing means, and because tests need it to arrange a non-empty corpus. An unconditional
// replace with an empty slice EMPTIES the corpus, which is correct for a caller that means it and a trap for one that does not;
// #767's surface has to decide that deliberately rather than inherit it.
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

// ReplaceIfEmpty writes docs as the corpus only if the corpus is currently empty, and reports whether it wrote.
//
// The check and the write are ONE transaction, which is the whole reason this exists as a method rather than as a caller that
// reads emptiness and then replaces. Done separately those two steps are a check-then-act: content committed between them is
// deleted, so a replica that read "empty" and then wrote would discard a rule authored in that window. The window is narrow at
// startup, and losing an operator's content is not a consequence worth a narrow window.
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

// PutDocument creates or replaces one document and bumps the version, in one transaction. Returns the new version.
//
// Per-document rather than through Replace, and the difference is not an optimisation. Replace takes the whole corpus, so an
// operator editing one rule through it would have to read every document, substitute one, and write them all back. Two operators
// editing different rules would then each write a corpus that omits the other's edit, and the later write would silently discard
// the earlier one. A single-row upsert has no such window: it touches the row it names and nothing else.
//
// The meta row is bumped FIRST, before the document, which is the lock order replaceWithin documents and which every mutation of
// this corpus has to share. Bumping it last here would give this path a documents-then-meta order against Replace's
// meta-then-documents, which is the ABBA deadlock that ordering was chosen to remove.
func (s *Store) PutDocument(ctx context.Context, doc api.Document) (int64, error) {
	return s.withVersionBump(ctx, "put", func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO rule_corpus_documents (path, content) VALUES (?, ?) AS new ON DUPLICATE KEY UPDATE content = new.content",
			doc.Path, string(doc.Content))
		if err != nil {
			return fmt.Errorf("upsert rule corpus document %q: %w", doc.Path, err)
		}
		return nil
	})
}

// DeleteDocument removes one document and bumps the version, in one transaction. Returns the new version.
//
// Reports api.ErrDocumentNotFound when the path held nothing, and the transaction is rolled back in that case so the version does
// NOT move. Both halves matter: a version bump with no content change would make every replica re-read the corpus to discover
// nothing had happened, and reporting success would tell an operator who mistyped a path that they had deleted a rule.
func (s *Store) DeleteDocument(ctx context.Context, path string) (int64, error) {
	return s.withVersionBump(ctx, "delete", func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM rule_corpus_documents WHERE path = ?", path)
		if err != nil {
			return fmt.Errorf("delete rule corpus document %q: %w", path, err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("delete rule corpus document %q rows affected: %w", path, err)
		}
		if affected == 0 {
			return fmt.Errorf("%w: %s", api.ErrDocumentNotFound, path)
		}
		return nil
	})
}

// withVersionBump runs write inside a transaction that has already bumped the version, and returns the new version.
//
// Shared by the two single-document mutations so neither can forget the bump or take its locks in the other order. A write that
// returns an error rolls the whole thing back, including the bump, which is what lets DeleteDocument report "not found" without
// moving the version.
func (s *Store) withVersionBump(ctx context.Context, op string, write func(tx *sqlx.Tx) error) (int64, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx for corpus %s: %w", op, err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, "UPDATE rule_corpus_meta SET version = version + 1 WHERE id = 1"); err != nil {
		return 0, fmt.Errorf("bump rule corpus version: %w", err)
	}
	var version int64
	if err := tx.GetContext(ctx, &version, "SELECT version FROM rule_corpus_meta WHERE id = 1"); err != nil {
		return 0, fmt.Errorf("read rule corpus version: %w", err)
	}
	if err := write(tx); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit corpus %s: %w", op, err)
	}
	return version, nil
}
