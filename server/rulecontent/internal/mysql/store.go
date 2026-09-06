// Package mysql is the rulecontent context's persistence for rule content: the corpus documents and the version counter a replica
// polls to notice another replica's change.
package mysql

import (
	"context"
	"database/sql"
	"errors"
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
	var rows []corpusRow
	if err := s.db.SelectContext(ctx, &rows,
		selectCorpusDocuments); err != nil {
		return nil, fmt.Errorf("select rule corpus documents: %w", err)
	}
	return documentsFromRows(rows)
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
	if err := setPackDigest(ctx, tx, api.PackDigest(api.VendoredDocuments(withDefaultSource(docs)))); err != nil {
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
	// Refused BEFORE the first row changes, and before the version moves, so a corpus carrying a source this version cannot
	// interpret is rejected whole rather than half-applied. Empty is not checked here: it is a supported input meaning "the
	// caller did not say", which withDefaultSource resolves to vendored below.
	for _, d := range docs {
		if d.Source != "" && !d.Source.Valid() {
			return 0, fmt.Errorf("%w: %s declares %q", api.ErrUnknownSource, d.Path, d.Source)
		}
	}
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
	// Defaulted through the one helper the digest also uses, rather than inline here. Two copies of "empty means vendored" is the
	// semantic duplication this codebase is most prone to, and the drift is silent in the worst direction: the rows would say one
	// thing about provenance and the recorded pack identity another.
	for _, d := range withDefaultSource(docs) {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO rule_corpus_documents (path, content, source) VALUES (?, ?, ?)",
			d.Path, string(d.Content), string(d.Source)); err != nil {
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
	// The digest covers the VENDORED half only, so an operator adding a rule later does not make the deployment look out of date.
	// Recorded in this transaction rather than after it, because a separate write can fail on its own and leave a corpus whose
	// content and stated identity disagree, silently.
	if err := setPackDigest(ctx, tx, api.PackDigest(api.VendoredDocuments(withDefaultSource(docs)))); err != nil {
		return false, 0, err
	}
	if err := tx.Commit(); err != nil {
		return false, 0, fmt.Errorf("commit conditional corpus replace: %w", err)
	}
	return true, version, nil
}

// checkPackIsShipped refuses a pack whose content claims to be an operator's.
//
// Shipped content is what a pack IS, so a document in one declaring otherwise is a contradiction rather than an edge case.
// Accepting it would let a build install rows that no operator wrote and that carry no upstream credit, which is the attribution
// failure #874 closed, arriving through a different door.
func checkPackIsShipped(pack []api.Document) error {
	for _, d := range pack {
		if d.Source != "" && d.Source != api.SourceVendored {
			return fmt.Errorf("%w: %s in a pack declares %q, and a pack is shipped content by definition",
				api.ErrUnknownSource, d.Path, d.Source)
		}
	}
	return nil
}

// packMinusOperatorRules returns the pack documents an upgrade may install: all of them except the ones whose RULE the operator
// has taken over, each marked as the shipped content it is. It also reports what it skipped, because that is a divergence from
// the shipped pack an operator is entitled to know about.
//
// Keyed on rule IDENTITY rather than on path, which is the correction review caught. A rule is identified by its file stem, so an
// operator's `authored/foo.yml` and a pack's `imported/foo.yml` are the same rule stored twice. Installing both does not shadow
// one with the other: the loader refuses the WHOLE corpus, the deployment falls back to the pack embedded in the binary, and
// every rule the operator wrote stops running. A path comparison misses that entirely, because the paths differ.
//
// Separate from the write so the decision is a pure function of what the pack carries and what is stored, which is the thing worth
// reading on its own: an upgrade's blast radius is defined here and nowhere else.
func packMinusOperatorRules(pack, stored []api.Document, identity api.RuleIdentity) (want []api.Document, skipped []string) {
	authored := make(map[string]struct{}, len(stored))
	for _, d := range stored {
		if d.Source == api.SourceAuthored {
			authored[identity.Identify(d.Path)] = struct{}{}
		}
	}
	want = make([]api.Document, 0, len(pack))
	for _, d := range pack {
		if _, taken := authored[identity.Identify(d.Path)]; taken {
			skipped = append(skipped, d.Path)
			continue
		}
		want = append(want, api.Document{Path: d.Path, Content: d.Content, Source: api.SourceVendored})
	}
	return want, skipped
}

// UpgradeVendoredTo installs pack as the shipped half of the corpus, leaving the operator's own content alone. It reports
// whether anything changed, and the version.
//
// Replacing only the shipped half is the whole point: an operator's rules are theirs and an upgrade is not a licence to discard
// them. Their TUNING survives for a different reason and without help here, because per-rule mode, severity overrides and
// exclusions live in detection_rule_settings keyed by rule id, not in these files.
//
// A path the operator has taken over is left to them. Writing their own version of a shipped rule makes that document theirs
// (#874), so a pack that still ships the same path must not quietly take it back: the upgrade skips those paths, and the operator
// keeps the rule they wrote until they delete it.
//
// The decision to write compares what this pack WOULD store against what is stored, rather than comparing the build's pack
// against the recorded digest, and the difference is what makes this idempotent. The recorded digest describes the shipped
// content actually held, so on a deployment that has overridden one shipped rule it can never equal the build's own pack digest;
// triggering on that comparison would re-run the upgrade on every boot, bumping the version each time and making every replica
// reload a corpus that did not change.
func (s *Store) UpgradeVendoredTo(
	ctx context.Context, pack []api.Document, identity api.RuleIdentity,
) (api.PackInstall, error) {
	if err := checkPackIsShipped(pack); err != nil {
		return api.PackInstall{}, err
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return api.PackInstall{}, fmt.Errorf("begin tx for pack upgrade: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Meta first, matching the lock order every mutation of this corpus takes (see replaceWithin). It also serialises this
	// against a concurrent replica running the same upgrade, so the second one reads the first one's result and no-ops.
	var version int64
	if err := tx.GetContext(ctx, &version, "SELECT version FROM rule_corpus_meta WHERE id = 1 FOR UPDATE"); err != nil {
		return api.PackInstall{}, fmt.Errorf("lock rule corpus meta: %w", err)
	}

	var rows []corpusRow
	if err := tx.SelectContext(ctx, &rows, selectCorpusDocuments); err != nil {
		return api.PackInstall{}, fmt.Errorf("read rule corpus documents for pack upgrade: %w", err)
	}
	stored, err := documentsFromRows(rows)
	if err != nil {
		return api.PackInstall{}, err
	}

	want, skipped := packMinusOperatorRules(pack, stored, identity)
	target := api.PackDigest(want)
	if target == api.PackDigest(api.VendoredDocuments(stored)) {
		return api.PackInstall{Version: version, Skipped: skipped}, nil
	}

	if _, err := tx.ExecContext(ctx, "UPDATE rule_corpus_meta SET version = version + 1 WHERE id = 1"); err != nil {
		return api.PackInstall{}, fmt.Errorf("bump rule corpus version: %w", err)
	}
	version++
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM rule_corpus_documents WHERE source = ?", string(api.SourceVendored)); err != nil {
		return api.PackInstall{}, fmt.Errorf("clear shipped rule corpus documents: %w", err)
	}
	for _, d := range want {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO rule_corpus_documents (path, content, source) VALUES (?, ?, ?)",
			d.Path, string(d.Content), string(api.SourceVendored)); err != nil {
			return api.PackInstall{}, fmt.Errorf("insert shipped rule corpus document %q: %w", d.Path, err)
		}
	}
	if err := setPackDigest(ctx, tx, target); err != nil {
		return api.PackInstall{}, err
	}
	if err := tx.Commit(); err != nil {
		return api.PackInstall{}, fmt.Errorf("commit pack upgrade: %w", err)
	}
	return api.PackInstall{Changed: true, Version: version, Skipped: skipped}, nil
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
func (s *Store) PutDocument(ctx context.Context, doc api.Document, expectedVersion int64) (int64, error) {
	return s.withVersionBump(ctx, "put", expectedVersion, func(tx *sqlx.Tx) (bool, error) {
		// Read before writing, because after the upsert the row says "authored" whatever it said before. A path that held a
		// SHIPPED document is the only case where this write shrinks the pack: a new path adds content that was never in it,
		// and a path that was already the operator's was never counted.
		wasVendored, err := pathHoldsVendored(ctx, tx, doc.Path)
		if err != nil {
			return false, err
		}
		// SourceAuthored is written here rather than taken from doc, and the caller cannot override it. A document arriving
		// through this method came through the authoring surface, which is the fact being recorded; letting a caller declare its
		// own provenance would make the licence attribution a claim rather than an observation.
		//
		// The source is updated on a replace as well as an insert, because writing over a vendored document makes it the
		// operator's: they now own its content, and crediting upstream for what they wrote would be the bug this exists to fix.
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO rule_corpus_documents (path, content, source) VALUES (?, ?, ?) AS new "+
				"ON DUPLICATE KEY UPDATE content = new.content, source = new.source",
			doc.Path, string(doc.Content), string(api.SourceAuthored)); err != nil {
			return false, fmt.Errorf("upsert rule corpus document %q: %w", doc.Path, err)
		}
		return wasVendored, nil
	})
}

// DeleteDocument removes one document and bumps the version, in one transaction. Returns the new version.
//
// Reports api.ErrDocumentNotFound when the path held nothing, and the transaction is rolled back in that case so the version does
// NOT move. Both halves matter: a version bump with no content change would make every replica re-read the corpus to discover
// nothing had happened, and reporting success would tell an operator who mistyped a path that they had deleted a rule.
func (s *Store) DeleteDocument(ctx context.Context, path string, expectedVersion int64) (int64, error) {
	return s.withVersionBump(ctx, "delete", expectedVersion, func(tx *sqlx.Tx) (bool, error) {
		// Read before deleting, for the same reason as the upsert: afterwards there is no row to ask.
		wasVendored, err := pathHoldsVendored(ctx, tx, path)
		if err != nil {
			return false, err
		}
		res, err := tx.ExecContext(ctx, "DELETE FROM rule_corpus_documents WHERE path = ?", path)
		if err != nil {
			return false, fmt.Errorf("delete rule corpus document %q: %w", path, err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return false, fmt.Errorf("delete rule corpus document %q rows affected: %w", path, err)
		}
		if affected == 0 {
			return false, fmt.Errorf("%w: %s", api.ErrDocumentNotFound, path)
		}
		return wasVendored, nil
	})
}

// withVersionBump runs write inside a transaction that has locked the meta row, checked the caller's expected version, and bumped
// it, and returns the new version.
//
// Shared by the two single-document mutations so neither can forget the bump, the check, or the lock order. A write that returns
// an error rolls the whole thing back, including the bump, which is what lets DeleteDocument report "not found" without moving the
// version.
//
// The meta row is taken with SELECT ... FOR UPDATE, and that single line is what makes the version check mean anything. It
// serialises every mutation of this corpus through one row, so a second writer BLOCKS until the first commits and then reads the
// version the first produced, rather than both reading the old one and both deciding they are current. Without the lock, the
// comparison below would be its own check-then-act, which is the race it exists to close.
//
// There is no bypass. An earlier revision took a negative sentinel meaning "do not check", on the theory that the seed would need
// it; the seed goes through ReplaceIfEmpty and never comes here, so the sentinel had no caller and was purely an escape hatch from
// the contract Writer states. A guard with no input that reaches it is dead code, and one that lets a future caller skip
// validation is worse than dead.
//
// The lock is COVERED, and it took the right kind of test to do it. The sequential stale-version tests pass with or without FOR
// UPDATE, because the comparison alone refuses a write that comes second. Two writers holding ONE version is the shape that
// distinguishes them: with the lock, exactly one wins; without it both read the same version under REPEATABLE READ, both conclude
// they are current, and both commit. Removing FOR UPDATE now fails that test with two documents stored where one was allowed.
func (s *Store) withVersionBump(
	ctx context.Context, op string, expectedVersion int64, write func(tx *sqlx.Tx) (bool, error),
) (int64, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx for corpus %s: %w", op, err)
	}
	defer tx.Rollback() //nolint:errcheck

	var current int64
	if err := tx.GetContext(ctx, &current, "SELECT version FROM rule_corpus_meta WHERE id = 1 FOR UPDATE"); err != nil {
		return 0, fmt.Errorf("lock rule corpus version: %w", err)
	}
	if current != expectedVersion {
		return 0, fmt.Errorf("%w: validated against %d, corpus is now at %d", api.ErrCorpusChanged, expectedVersion, current)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE rule_corpus_meta SET version = version + 1 WHERE id = 1"); err != nil {
		return 0, fmt.Errorf("bump rule corpus version: %w", err)
	}
	version := current + 1
	packMoved, err := write(tx)
	if err != nil {
		return 0, err
	}
	// Re-derived here rather than in each mutation, for the same reason the version bump is: neither single-document path can
	// forget it. Both of them can change the VENDORED set even though neither looks like it does. PutDocument over a shipped
	// document reclassifies that row as authored, and DeleteDocument can remove a shipped one; in both cases the corpus no
	// longer holds the pack it did, and a digest left alone would keep asserting it does. That assertion is the one thing the
	// digest exists to make, so a stale one is worse than none.
	//
	// Only when the shipped set actually moved, which is the common case NOT moving: an operator adding or editing a rule of
	// their own leaves the pack alone. An earlier revision rescanned unconditionally and justified it by claiming that deciding
	// whether the set moved meant reading the documents anyway. That was simply wrong, and review was right to call it: the
	// answer comes from the ONE row being written, which the caller has already had to look at.
	//
	// The cost of getting this wrong is not theoretical. The rescan materialises every document's content inside the
	// transaction holding the meta row's FOR UPDATE, which serialises every mutation of this corpus; at the validator's bound
	// of 4096 documents times 64 KiB that is 256 MiB read under the one lock every other writer is waiting on.
	if packMoved {
		if err := recordPackDigestWithin(ctx, tx); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit corpus %s: %w", op, err)
	}
	return version, nil
}

// PackDigest returns the identity of the vendored content this corpus holds, or "" when none has been recorded.
//
// Empty is a real answer rather than a missing one: a corpus seeded before provenance was recorded holds SOME vendored
// generation and nothing wrote down which, so reporting a digest would be inventing one. A caller comparing against the build's
// pack has to treat empty as "unknown, therefore not known to be current" rather than as a mismatch or a match.
//
// No production caller yet: the writes record the digest, and the surface that READS it to decide whether a deployment is running
// the current pack is the upgrade path (issue #768). It ships here rather than with that work because the value is only
// trustworthy if it has been recorded from the first write onward; adding the reader later is additive, whereas backfilling a
// digest nobody wrote is not possible.
func (s *Store) PackDigest(ctx context.Context) (string, error) {
	var digest string
	if err := s.db.GetContext(ctx, &digest, "SELECT pack_digest FROM rule_corpus_meta WHERE id = 1"); err != nil {
		return "", fmt.Errorf("select rule corpus pack digest: %w", err)
	}
	return digest, nil
}

// pathHoldsVendored reports whether the corpus currently stores content that SHIPPED at this path.
//
// It answers exactly the question the two single-document mutations need: whether the change they are about to make moves the
// shipped set, and therefore whether the pack identity has to be re-derived. A missing row is not vendored, which is the right
// answer rather than a convenient one: adding a document the pack never contained does not change the pack.
//
// An unrecognised source is refused here too. Reporting "not vendored" for a value this version cannot interpret would let the
// digest silently stop describing a document that may well be part of the pack.
func pathHoldsVendored(ctx context.Context, tx *sqlx.Tx, path string) (bool, error) {
	var stored string
	switch err := tx.GetContext(ctx, &stored, "SELECT source FROM rule_corpus_documents WHERE path = ?", path); {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("read source of rule corpus document %q: %w", path, err)
	}
	source := api.Source(stored)
	if !source.Valid() {
		return false, fmt.Errorf("%w: %s has source %q", api.ErrUnknownSource, path, stored)
	}
	return source == api.SourceVendored, nil
}

// recordPackDigestWithin re-derives the pack identity from the documents the transaction will commit, and records it.
//
// It reads the rows back rather than taking them from the caller because the single-document mutations only know their own
// document: what the digest describes is the whole vendored set AFTER the change, which only the table has. The read is inside
// the caller's transaction, so it sees that change and nothing else's.
//
// An unknown source is refused here too, and deliberately so rather than skipped: the mutation would otherwise be the one path
// that can commit while a row this version cannot interpret sits in the corpus it just re-identified.
func recordPackDigestWithin(ctx context.Context, tx *sqlx.Tx) error {
	var rows []corpusRow
	if err := tx.SelectContext(ctx, &rows,
		selectCorpusDocuments); err != nil {
		return fmt.Errorf("read rule corpus documents for pack digest: %w", err)
	}
	docs, err := documentsFromRows(rows)
	if err != nil {
		return err
	}
	return setPackDigest(ctx, tx, api.PackDigest(api.VendoredDocuments(docs)))
}

// setPackDigest records which vendored pack the corpus now holds, inside the caller's transaction.
//
// Always written in the SAME transaction as the documents it describes. Recorded separately it would be a second write that can
// fail on its own, leaving a corpus whose content and stated identity disagree, and the disagreement is silent: the deployment
// would report a pack it is not running.
func setPackDigest(ctx context.Context, tx *sqlx.Tx, digest string) error {
	if _, err := tx.ExecContext(ctx, "UPDATE rule_corpus_meta SET pack_digest = ? WHERE id = 1", digest); err != nil {
		return fmt.Errorf("record rule corpus pack digest: %w", err)
	}
	return nil
}

// withDefaultSource applies the same defaulting replaceWithin does, so the digest is taken over the documents that will actually
// be stored rather than over the caller's un-defaulted view of them.
//
// It exists because the two would otherwise disagree in exactly one case, and silently: a seed hands over documents with no
// source, replaceWithin stores them as vendored, and a digest computed over the raw input would find no vendored documents at all
// and record the digest of an empty pack. The deployment would then hold the whole corpus and claim to hold nothing.
func withDefaultSource(docs []api.Document) []api.Document {
	out := make([]api.Document, 0, len(docs))
	for _, d := range docs {
		if d.Source == "" {
			d.Source = api.SourceVendored
		}
		out = append(out, d)
	}
	return out
}

// documentsFromRows turns stored rows into documents, refusing any whose provenance this version does not recognise.
//
// One implementation for both readers. Written twice it was already drifting in its error type alone, and the mutation run said
// so: the same guard appearing twice means a mutant cannot be aimed at it, which is the same ambiguity a maintainer would face.
//
// The refusal is on the way OUT, and it guards something the write-side check cannot. That one stops THIS version from storing a
// value it does not understand; this one stops a row written by a version that knew more, or edited by hand, from being
// half-interpreted: credited to upstream by attribution while excluded from the pack digest.
func documentsFromRows(rows []corpusRow) ([]api.Document, error) {
	docs := make([]api.Document, 0, len(rows))
	for _, r := range rows {
		source := api.Source(r.Source)
		if !source.Valid() {
			return nil, fmt.Errorf("%w: %s has source %q", api.ErrUnknownSource, r.Path, r.Source)
		}
		docs = append(docs, api.Document{Path: r.Path, Content: []byte(r.Content), Source: source})
	}
	return docs, nil
}

// selectCorpusDocuments is the one definition of how a corpus is read. Both readers take it: the plain one and the one inside a
// mutation's transaction. Two copies would drift as the stored shape changes, and the ordering is not incidental either, since
// every replica has to load the same corpus in the same order.
const selectCorpusDocuments = "SELECT path, content, source FROM rule_corpus_documents ORDER BY path"

// corpusRow is one stored rule-content row, shared by the queries that read them so the column set is stated once.
type corpusRow struct {
	Path    string `db:"path"`
	Content string `db:"content"`
	Source  string `db:"source"`
}
