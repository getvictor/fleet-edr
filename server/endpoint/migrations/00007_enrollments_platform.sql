-- +goose Up
-- Record the agent's platform on the enrollment row so the host inventory and UI can show it and detection can scope by host platform
-- (ADR-0018, Phase 0 of Windows support). The agent reports it at enrollment; the server normalizes an absent value to darwin. NOT NULL
-- DEFAULT '' keeps rows enrolled before this migration valid; consumers treat an empty value as darwin, the legacy-agent default.
ALTER TABLE enrollments ADD COLUMN platform VARCHAR(16) NOT NULL DEFAULT '' AFTER os_version;

-- +goose Down
ALTER TABLE enrollments DROP COLUMN platform;
