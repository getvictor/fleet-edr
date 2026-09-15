-- +goose Up
-- Desired network containment per host (issue #948). A row exists only for a host whose containment was ever changed: a host with
-- none is not contained and is sent nothing. version orders one host's states; updated_at is the state's change time on the database
-- clock and becomes the delivered epoch, strictly later than the previous change so ordering by epoch agrees with ordering by version.
--
-- A new table, so it ships single-step under ADR-0009. No down section, per the same ADR.

-- +goose StatementBegin
CREATE TABLE host_containment (
	host_id    VARCHAR(255)  NOT NULL,
	contained  BOOLEAN       NOT NULL,
	version    BIGINT        NOT NULL,
	reason     VARCHAR(1024) NOT NULL,
	updated_by VARCHAR(255)  NOT NULL,
	updated_at DATETIME(6)   NOT NULL,
	PRIMARY KEY (host_id)
);
-- +goose StatementEnd
