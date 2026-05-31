-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS widgets (
	id   BIGINT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(64) NOT NULL
);
-- +goose StatementEnd
