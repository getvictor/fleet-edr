-- +goose Up
-- Add the platform discriminator to the work queue so it survives the claim to rule evaluation (ADR-0018, Phase 0 of Windows support).
-- The engine scopes rules by platform, and events reach it only through this queue, so the column must ride the envelope here rather
-- than be resolved per host at claim time. NOT NULL DEFAULT '' keeps rows written before this migration claimable; intake normalizes an
-- empty platform to darwin, and the engine treats an empty value as darwin, so a pre-migration row is scoped as macOS as intended.
ALTER TABLE event_queue ADD COLUMN platform VARCHAR(16) NOT NULL DEFAULT '' AFTER event_type;

-- +goose Down
ALTER TABLE event_queue DROP COLUMN platform;
