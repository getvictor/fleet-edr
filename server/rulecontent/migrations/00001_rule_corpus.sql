-- +goose Up
-- Rule content acquires its own storage, which is what makes it an aggregate rather than a projection of the catalog and is the
-- trigger ADR-0021 named for carving `rulecontent` out of `rules` (issue #766, Phase 5 of the rule-format epic #756).
--
-- Two tables, mirroring the shape detection_config uses for the same job. rule_corpus_documents holds the content itself, one row
-- per rule file, keyed by the path the loader reads it under so the existing Sigma loader can be pointed at storage instead of the
-- embedded corpus without changing how it parses. rule_corpus_meta holds a single version counter that a replica polls to notice
-- another replica's change, so convergence costs one indexed read per interval rather than reloading the whole corpus.
--
-- The content column is MEDIUMTEXT rather than TEXT: TEXT caps at 65,535 BYTES, and while today's largest vendored rule is far
-- under that, a rule file is operator- and community-authored content whose size this schema should not be the thing to bound.
-- Bounding it is a validation concern with a policy behind it (issue #767), not a column width chosen by accident.

-- path carries a BINARY collation, not the table default. The default here is utf8mb4_0900_ai_ci, which is case- and
-- accent-insensitive, and a path is neither: it is an fs.FS identity, compared and ordered bytewise by both the filesystem and the
-- loader. Under the insensitive default, `imported/Foo.yml` and `imported/foo.yml` collide on this primary key, so a corpus holding
-- both fails to store at all, and because a replace is all-or-nothing that takes the whole corpus down to the embedded fallback.
-- The ordering diverges too: the loader sorts bytewise, so a mixed-case corpus would load in a different order from storage than
-- from the build, and registration order is observable in the operator catalog and the generated reference.
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS rule_corpus_documents (
	path       VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
	content    MEDIUMTEXT   NOT NULL,
	updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (path)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
-- +goose StatementEnd

-- Single row, id pinned to 1, exactly as detection_config_meta does it: the counter is a property of the corpus as a whole, so
-- there is nothing for a second row to mean.
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS rule_corpus_meta (
	id      TINYINT NOT NULL,
	version BIGINT  NOT NULL DEFAULT 0,
	PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
-- +goose StatementEnd

-- Seeded so a reader never has to distinguish "no counter row yet" from "version zero".
-- +goose StatementBegin
INSERT IGNORE INTO rule_corpus_meta (id, version) VALUES (1, 0);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS rule_corpus_documents;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS rule_corpus_meta;
-- +goose StatementEnd
