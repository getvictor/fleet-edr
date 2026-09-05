-- +goose Up
-- Rule content records where each document came from, which two problems both need and neither can be fixed without (#874, #768).
--
-- #874: every document loaded from storage became an importedRule, whose origin is hardcoded to the upstream project. That was
-- correct while the corpus could only hold vendored content. #873 gave it a write path and #875 gave operators a way to use it, so
-- "stored means imported" stopped being true and nothing said so. The credit is how this product honours the Detection Rule
-- License, so crediting upstream for an operator's own rule misstates the licensing of work that was never under it.
--
-- #768: SeedFrom is the only writer of vendored content and it goes through ReplaceIfEmpty, so a deployment seeds once on its
-- first boot and keeps that generation forever. Upgrading the pack means replacing the vendored documents and leaving the
-- authored ones alone, which is not expressible until the two can be told apart.

-- source is RECORDED, not derived, and that is the load-bearing choice rather than a storage detail.
--
-- The obvious alternative is to read provenance off the path: anything under `imported/` is vendored. #873 deliberately ruled that
-- out. A rule's identity is its file STEM and not its path, and the load was widened to walk the whole stored set precisely so
-- authored content need not live under a directory named `imported`. A path prefix would therefore contradict the identity rule
-- AND be chosen by the very operator it is meant to describe: writing to `imported/mine.yml` would launder an authored rule into a
-- vendored one, and with it a licence attribution.
--
-- How a document ARRIVED is a fact only the store observes, so the store is where it belongs.
--
-- Defaulting to 'vendored' is for the rows already here. Every document predating this migration was written by SeedFrom, because
-- the authoring surface (#875) shipped after it and the only other writer is Replace, which had no production caller. Backfilling
-- them as vendored is therefore a statement of fact rather than a guess, and it is the safe direction besides: mislabelling an
-- authored rule as vendored over-credits upstream, which is visible, where the reverse silently drops a licence obligation.
-- On the rolling upgrade ADR-0009 requires this to survive: during cutover, binary N and binary N+1 run against one MySQL, so a
-- column added with a DEFAULT is a hazard whenever N still writes the table without naming it. N's write would take the default
-- and be recorded as vendored, and an operator authoring a rule against an old replica in that window would be credited to
-- SigmaHQ permanently, which is precisely the bug this migration ends.
--
-- That hazard cannot occur here, and the reason is checkable rather than a judgement: no released binary writes this table at
-- all. `rule_corpus_documents` does not exist in v0.4.0 or v0.4.0-rc.1; the table, its store, and PutDocument were all introduced
-- by #847, which is in no release tag, so the migration that creates the table and this one that adds the column ship in the same
-- release. There is no binary N with a write path to skew.
--
-- It will NOT stay moot. Once this release ships, an old replica does have PutDocument, and the next column added to this table
-- has to be expand-contract: nullable, written explicitly by the new binary, tightened in a later release.
-- +goose StatementBegin
ALTER TABLE rule_corpus_documents
	ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'vendored';
-- +goose StatementEnd

-- pack_digest identifies the vendored content a corpus holds, and is derived from that content rather than declared beside it.
--
-- A hand-maintained version would have to be bumped by whoever edits the corpus, and the failure mode of forgetting is silent: a
-- deployment believes it is current while running different rules. A digest cannot be forgotten, because it is a function of the
-- thing it describes.
--
-- Empty until the seed or an upgrade records one, which is honest for a corpus that predates this column: the deployment holds
-- SOME vendored generation and nothing recorded which, so claiming a digest would be inventing one. The next upgrade path (#768)
-- treats an empty digest as "unknown, therefore not current".
-- +goose StatementBegin
ALTER TABLE rule_corpus_meta
	ADD COLUMN pack_digest VARCHAR(64) NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- Forward-only migrations (ADR-0009), and this one has a specific reason beyond the policy. Dropping `source` would discard which
-- rules an operator wrote, and that is not recoverable by re-running the Up: every surviving row would come back defaulted to
-- vendored, so an operator's own rules would be credited upstream again. That is the exact misattribution this migration exists to
-- end. The rollback path is restore-from-backup; this Down is intentionally a no-op, as 00012_alerts_origin.sql is for the same
-- reason.
