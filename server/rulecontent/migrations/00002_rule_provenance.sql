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
-- +goose StatementBegin
ALTER TABLE rule_corpus_documents DROP COLUMN source;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE rule_corpus_meta DROP COLUMN pack_digest;
-- +goose StatementEnd
