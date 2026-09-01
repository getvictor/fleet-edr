-- +goose Up
-- Carry rule attribution on the alert row (issue #765). The vendored corpus ships under the Detection Rule License, which requires
-- crediting the rule's author wherever a match is displayed, and the surface that displays matches is the alert view.
--
--   origin: who the rule came from, as of the moment the alert was raised. "SigmaHQ, by <author>" for an imported rule, "Fleet EDR"
--     for one this project wrote. The engine stamps it from the rule (rulesapi.OriginOf); it is never taken from the finding, so a
--     rule cannot forge, reassign or suppress its own credit.
--
-- Denormalized rather than joined from the catalog at read time, which is the same choice already made for title, description and
-- severity. A join fails OPEN for the obligation this column exists to meet: an alert whose rule has since left the catalog would
-- render with no credit at all, and #766 (runtime-loaded rule packs) makes that a routine occurrence rather than an upgrade-day
-- edge case. A stored value fails safe, since the worst case is crediting the author who was named when the match happened, which
-- is the historically accurate answer anyway.
--
-- No backfill, and that is a property rather than an omission: every imported rule ships in monitor mode (issue #764), and monitor
-- resolution returns before persistence, so no alert row raised by an imported rule exists to credit. Rows predating this migration
-- were all raised by rules this project wrote and keep the empty default; they are the one case a reader may see uncredited, and
-- they are ours. Left empty rather than defaulted to 'Fleet EDR' so the column distinguishes "raised before attribution existed"
-- from "raised by us", which a blanket backfill would erase.
--
-- Not part of uk_alerts_dedup: origin is a function of rule_id, which is already in the key, so including it could only ever split
-- one logical alert into two rows after an upstream author change.

-- +goose StatementBegin
ALTER TABLE alerts
	ADD COLUMN origin VARCHAR(255) NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- Forward-only migrations (ADR-0009). Dropping the column would discard the attribution captured on every alert raised since the
-- upgrade, which is the licence record itself; this Down is intentionally a no-op.
