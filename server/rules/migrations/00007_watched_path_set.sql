-- +goose Up
-- The watched-path set (issue #998, ADR-0008 step 4): file paths the extension's file-tamper client watches on top of the ones built
-- into it. One row holding the whole set, because the set is replaced whole, pushed to hosts whole, and versioned as a whole: a host
-- reports the version it took, and a version names exactly one list of paths.
--
-- paths is JSON rather than a row per path so the version and the list change in one statement and cannot disagree. Order within the
-- array is preserved by MySQL's JSON type; only object keys are reordered, which the decoder does not depend on.
--
-- A new table, so no online-DDL concern. The row is seeded at version 0 with an empty set, which is what every host already watches.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS watched_path_set (
	id         TINYINT      NOT NULL PRIMARY KEY,
	version    BIGINT       NOT NULL DEFAULT 0,
	paths      JSON         NOT NULL,
	updated_at TIMESTAMP(6) NULL,
	updated_by VARCHAR(255) NOT NULL DEFAULT ''
);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT IGNORE INTO watched_path_set (id, version, paths) VALUES (1, 0, JSON_ARRAY());
-- +goose StatementEnd
