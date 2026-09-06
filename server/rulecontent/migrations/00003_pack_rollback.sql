-- +goose Up
-- Retain the shipped content an upgrade replaces, so a bad pack is recoverable (#768).
--
-- The upgrade in #880 installs the pack a build carries over the shipped half of the corpus. That is the right default and it is
-- one-way: once the newer pack is in, the generation it replaced is gone, and an operator who finds a rule in it noisy or wrong
-- has nothing to go back to short of restoring a database backup. "Make a bad one recoverable" is the half of #768 this adds.
--
-- ONE generation is retained rather than a history. The issue asks to roll back to the previous version, and a deeper history
-- would need a retention policy, a way to name a generation, and a UI to choose between them: all of that is speculative until
-- someone asks to skip back two. Restoring the previous set is what makes a bad upgrade survivable, and it is the whole ask.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS rule_corpus_previous_documents (
	path    VARCHAR(255) NOT NULL,
	content LONGTEXT     NOT NULL,
	PRIMARY KEY (path)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
-- +goose StatementEnd

-- The path column collates the way rule_corpus_documents.path does NOT, and that difference is deliberate rather than an
-- oversight: this table is a snapshot to restore verbatim, never a set to look rules up in. Nothing joins it to the live corpus or
-- keys a rule id off it, so the case-sensitivity that matters there does not arise here. A rollback reads every row and writes
-- them back through the same path that any other shipped content takes, where the live table's collation applies again.
-- +goose StatementBegin
ALTER TABLE rule_corpus_previous_documents
	MODIFY COLUMN path VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL;
-- +goose StatementEnd

-- previous_pack_digest identifies the retained generation, and empty means there is none to go back to.
--
-- A deployment that has never upgraded is the ordinary case for that: it seeded once and is still running what it seeded, so
-- there is no previous generation and a rollback has nothing to restore. Reporting that plainly is better than restoring an empty
-- set, which would leave the deployment detecting nothing.
-- +goose StatementBegin
ALTER TABLE rule_corpus_meta
	ADD COLUMN previous_pack_digest VARCHAR(64) NOT NULL DEFAULT '';
-- +goose StatementEnd

-- declined_pack_digest is what makes a rollback survive the next restart, and without it rollback would be theatre.
--
-- The upgrade decides by comparing what this build's pack would store against what is stored. After a rollback those differ by
-- construction, so the very next start would reinstall the pack the operator just rejected, and every start after that. The
-- operator would have no way to stay on the older generation except never restarting.
--
-- So a rollback records WHICH pack was declined, by the digest of the build's pack as shipped, and the upgrade skips a pack whose
-- digest matches. It is keyed on the pack rather than on a boolean because the decision is about that pack and not about upgrades
-- in general: the next release ships a different one, its digest does not match, and it installs normally. An operator does not
-- have to remember to switch upgrades back on, which is the kind of latch that silently leaves a fleet on old detections.
-- +goose StatementBegin
ALTER TABLE rule_corpus_meta
	ADD COLUMN declined_pack_digest VARCHAR(64) NOT NULL DEFAULT '';
-- +goose StatementEnd

-- installed_pack_digest is the digest of the build pack the last upgrade installed FROM, before operator overrides were filtered
-- out of it. pack_digest describes the shipped content actually stored, which is the right thing for integrity and the wrong
-- thing for this: on a deployment holding an override the two can never be equal, so a rollback could not name the pack it was
-- declining. This is that name.
-- +goose StatementBegin
ALTER TABLE rule_corpus_meta
	ADD COLUMN installed_pack_digest VARCHAR(64) NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- Forward-only migrations (ADR-0009). Dropping these would discard the generation an operator can roll back to and the record of
-- a pack they declined, so re-applying would silently reinstall content they rejected. The rollback path is restore-from-backup;
-- this Down is intentionally a no-op, as 00002_rule_provenance.sql is for the same class of reason.
