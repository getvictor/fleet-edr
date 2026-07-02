-- +goose Up
-- Add the platform discriminator to the event archive so alert-evidence reads (EventsByIDs) and per-process correlation return the
-- full platform-tagged envelope (ADR-0018, Phase 0 of Windows support). LowCardinality(String) matches host_id/event_type: the value
-- set is tiny (darwin, windows, linux). DEFAULT '' keeps rows written before this migration readable; consumers treat an empty value
-- as darwin, the legacy-agent default.
ALTER TABLE events ADD COLUMN IF NOT EXISTS platform LowCardinality(String) DEFAULT '' AFTER event_type;

-- +goose Down
ALTER TABLE events DROP COLUMN IF EXISTS platform;
