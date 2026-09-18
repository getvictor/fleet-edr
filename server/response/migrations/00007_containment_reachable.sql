-- +goose Up
-- The reachable-address set (issue #1059): addresses a contained host may still reach, on top of the lifeline built into containment.
-- One row holding the whole set, because the set is replaced whole, delivered whole with each host's containment state, and versioned
-- as a whole: a version names exactly one list of addresses, and a host either holds that version or does not.
--
-- addresses is JSON rather than a row per address so the version and the list change in one statement and cannot disagree. Order
-- within the array is preserved by MySQL's JSON type; only object keys are reordered, which the decoder does not depend on. This
-- mirrors watched_path_set (issue #998), which is the same shape of deployment-wide set pushed to hosts.
--
-- Deployment-wide rather than per host: an incident responder keeps the same few systems reachable whatever host they contain, and a
-- per-host list would be edited under incident pressure on every containment. Per-host entries are out of scope for the issue.
--
-- A new table, so no online-DDL concern. The row is seeded at version 0 with an empty set, which is the lifeline every contained host
-- already gets and therefore a no-op for hosts contained before this shipped.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS containment_reachable_set (
	id         TINYINT      NOT NULL PRIMARY KEY,
	version    BIGINT       NOT NULL DEFAULT 0,
	addresses  JSON         NOT NULL,
	updated_at TIMESTAMP(6) NULL,
	updated_by VARCHAR(255) NOT NULL DEFAULT ''
);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT IGNORE INTO containment_reachable_set (id, version, addresses) VALUES (1, 0, JSON_ARRAY());
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS containment_reachable_set;
-- +goose StatementEnd
