-- +goose Up
-- +goose StatementBegin
-- A delivery can now describe a host health episode instead of an alert (issue #778).
--
-- The outbox was built when every delivery was an alert, and three parts of its shape encode that. alert_id was NOT NULL with a
-- foreign key to alerts; that id was part of the key that makes an enqueue idempotent; and a destination's event types were a
-- closed SET naming only alert events. A health episode has no alert row, and it is owned by the endpoint context, so it cannot be
-- given one without putting the fault back in the table it was deliberately moved out of.
--
-- So a delivery names exactly ONE subject. alert_id becomes nullable and keeps its foreign key, which constrains only the rows that
-- set it. health_episode_id joins it with NO foreign key: episodes live in endpoint, and this schema belongs to detection, which
-- does not reference another context's tables. The check constraint is what stops a row naming both or neither, which the store
-- would otherwise have to be trusted never to write.
--
-- Each subject gets its own idempotency key. The existing (alert_id, destination_id, dedup_key) key cannot serve a health delivery,
-- because MySQL treats NULLs in a unique index as distinct, so every health row would be unique on it and nothing would collapse.
-- The new key has the same shape over health_episode_id, and for alert rows it is the one full of NULLs, so neither key constrains
-- the other kind.
ALTER TABLE webhook_delivery
	MODIFY COLUMN alert_id BIGINT NULL,
	ADD COLUMN health_episode_id BIGINT NULL AFTER alert_id,
	ADD UNIQUE KEY uk_webhook_delivery_health_event (health_episode_id, destination_id, dedup_key),
	ADD CONSTRAINT chk_webhook_delivery_one_subject
		CHECK ((alert_id IS NULL) <> (health_episode_id IS NULL));
-- +goose StatementEnd

-- +goose StatementBegin
-- The event types a destination can subscribe to. Appended at the END of the SET, not inserted: MySQL stores a SET as a bitmask over
-- member position, so reordering existing members would silently change what every stored subscription means, while appending leaves
-- each existing bit where it was. Only the opening edge is added. An episode closing is recorded by the endpoint context's status
-- check-in, which cannot write into this outbox without reversing the dependency between the two contexts, and a member nothing can
-- ever deliver would be a subscription that silently never fires.
ALTER TABLE webhook_destination
	MODIFY COLUMN event_types SET('alert.created', 'alert.status_changed', 'host.health_episode_opened')
		NOT NULL DEFAULT 'alert.created';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- A destination subscribed ONLY to the health event would be left with an empty set, which the column's NOT NULL still accepts but no
-- delivery would ever match; health rows cannot survive the alert_id NOT NULL restore at all. Both are removed first, so the down
-- migration succeeds instead of failing halfway on data it did not anticipate.
DELETE FROM webhook_delivery WHERE health_episode_id IS NOT NULL;
UPDATE webhook_destination
	SET event_types = TRIM(BOTH ',' FROM REPLACE(CONCAT(',', event_types, ','), ',host.health_episode_opened,', ','))
	WHERE FIND_IN_SET('host.health_episode_opened', event_types);
ALTER TABLE webhook_destination
	MODIFY COLUMN event_types SET('alert.created', 'alert.status_changed') NOT NULL DEFAULT 'alert.created';
ALTER TABLE webhook_delivery
	DROP CHECK chk_webhook_delivery_one_subject,
	DROP INDEX uk_webhook_delivery_health_event,
	DROP COLUMN health_episode_id,
	MODIFY COLUMN alert_id BIGINT NOT NULL;
-- +goose StatementEnd
