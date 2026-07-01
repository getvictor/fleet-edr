package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	detapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/webhook"
)

// Errors surfaced by the webhook destination store. Handlers map these to 4xx responses; the sealer-unset error is a deployment
// misconfiguration (no root secret) rather than operator input.
var (
	ErrWebhookNotFound      = errors.New("detection: webhook destination not found")
	ErrWebhookSealerUnset   = errors.New("detection: webhook sealer not configured")
	ErrWebhookName          = errors.New("detection: webhook destination requires a name")
	ErrWebhookSecretMissing = errors.New("detection: webhook destination requires a signing secret")
	ErrWebhookEventTypes    = errors.New("detection: webhook destination requires at least one valid event type")
	ErrWebhookSeverity      = errors.New("detection: invalid webhook minimum severity")
)

var validWebhookSeverities = map[string]bool{
	detapi.SeverityLow: true, detapi.SeverityMedium: true, detapi.SeverityHigh: true, detapi.SeverityCritical: true,
}

var validWebhookEventTypes = map[string]bool{
	detapi.WebhookEventAlertCreated: true, detapi.WebhookEventAlertStatusChanged: true,
}

type webhookDestinationRow struct {
	ID           int64     `db:"id"`
	Name         string    `db:"name"`
	URL          string    `db:"url"`
	SecretSealed []byte    `db:"secret_sealed"`
	EventTypes   string    `db:"event_types"`
	MinSeverity  string    `db:"min_severity"`
	Enabled      bool      `db:"enabled"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

func (r webhookDestinationRow) toAPI() detapi.WebhookDestination {
	return detapi.WebhookDestination{
		ID:          r.ID,
		Name:        r.Name,
		URL:         r.URL,
		EventTypes:  splitSet(r.EventTypes),
		MinSeverity: r.MinSeverity,
		Enabled:     r.Enabled,
		SecretSet:   len(r.SecretSealed) > 0,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// splitSet turns a MySQL SET value (comma-joined) into a slice, returning nil for the empty set so a destination with no event types
// round-trips as an empty JSON array rather than [""].
func splitSet(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

const webhookDestinationCols = "id, name, url, secret_sealed, event_types, min_severity, enabled, created_at, updated_at"

// validateDestinationInput checks the operator input and returns the normalized event-types SET string and minimum severity. URL
// validation reuses the delivery-side SSRF guard so a non-https or blocked-literal URL is rejected at save time.
func validateDestinationInput(in detapi.WebhookDestinationInput) (eventTypes, minSeverity string, err error) {
	if strings.TrimSpace(in.Name) == "" {
		return "", "", ErrWebhookName
	}
	if err := webhook.ValidateURL(in.URL); err != nil {
		return "", "", err
	}
	minSeverity = in.MinSeverity
	if minSeverity == "" {
		minSeverity = detapi.SeverityLow
	}
	if !validWebhookSeverities[minSeverity] {
		return "", "", fmt.Errorf("%w: %q", ErrWebhookSeverity, in.MinSeverity)
	}
	if len(in.EventTypes) == 0 {
		return "", "", ErrWebhookEventTypes
	}
	for _, et := range in.EventTypes {
		if !validWebhookEventTypes[et] {
			return "", "", fmt.Errorf("%w: %q", ErrWebhookEventTypes, et)
		}
	}
	return strings.Join(in.EventTypes, ","), minSeverity, nil
}

// CreateWebhookDestination validates and inserts a destination, sealing its signing secret at rest. It requires the sealer to be
// configured and a non-empty secret; the plaintext secret never leaves this method.
func (s *Store) CreateWebhookDestination(ctx context.Context, in detapi.WebhookDestinationInput) (int64, error) {
	if s.webhookSealer == nil {
		return 0, ErrWebhookSealerUnset
	}
	if in.Secret == "" {
		return 0, ErrWebhookSecretMissing
	}
	eventTypes, minSeverity, err := validateDestinationInput(in)
	if err != nil {
		return 0, err
	}
	sealed, err := s.webhookSealer.Seal([]byte(in.Secret))
	if err != nil {
		return 0, fmt.Errorf("seal webhook secret: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO webhook_destination (name, url, secret_sealed, event_types, min_severity, enabled)
		VALUES (?, ?, ?, ?, ?, ?)`,
		in.Name, in.URL, sealed, eventTypes, minSeverity, in.Enabled)
	if err != nil {
		return 0, fmt.Errorf("insert webhook destination: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("webhook destination last id: %w", err)
	}
	return id, nil
}

// ListWebhookDestinations returns every destination ordered by id. The signing secret is not selected into the read model.
func (s *Store) ListWebhookDestinations(ctx context.Context) ([]detapi.WebhookDestination, error) {
	var rows []webhookDestinationRow
	if err := s.db.SelectContext(ctx, &rows, "SELECT "+webhookDestinationCols+" FROM webhook_destination ORDER BY id"); err != nil {
		return nil, fmt.Errorf("list webhook destinations: %w", err)
	}
	out := make([]detapi.WebhookDestination, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.toAPI())
	}
	return out, nil
}

// GetWebhookDestination returns one destination or ErrWebhookNotFound.
func (s *Store) GetWebhookDestination(ctx context.Context, id int64) (detapi.WebhookDestination, error) {
	var r webhookDestinationRow
	err := s.db.GetContext(ctx, &r, "SELECT "+webhookDestinationCols+" FROM webhook_destination WHERE id = ?", id)
	if errors.Is(err, sql.ErrNoRows) {
		return detapi.WebhookDestination{}, ErrWebhookNotFound
	}
	if err != nil {
		return detapi.WebhookDestination{}, fmt.Errorf("get webhook destination %d: %w", id, err)
	}
	return r.toAPI(), nil
}

// UpdateWebhookDestination updates a destination. An empty input Secret keeps the stored secret so the operator can edit other fields
// without re-entering it; a non-empty Secret rotates it (and requires the sealer). Returns ErrWebhookNotFound for an unknown id.
func (s *Store) UpdateWebhookDestination(ctx context.Context, id int64, in detapi.WebhookDestinationInput) error {
	eventTypes, minSeverity, err := validateDestinationInput(in)
	if err != nil {
		return err
	}
	var exists int64
	if err := s.db.GetContext(ctx, &exists, "SELECT id FROM webhook_destination WHERE id = ?", id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrWebhookNotFound
		}
		return fmt.Errorf("check webhook destination %d: %w", id, err)
	}
	if in.Secret == "" {
		_, err = s.db.ExecContext(ctx, `
			UPDATE webhook_destination SET name = ?, url = ?, event_types = ?, min_severity = ?, enabled = ? WHERE id = ?`,
			in.Name, in.URL, eventTypes, minSeverity, in.Enabled, id)
		if err != nil {
			return fmt.Errorf("update webhook destination %d: %w", id, err)
		}
		return nil
	}
	if s.webhookSealer == nil {
		return ErrWebhookSealerUnset
	}
	sealed, err := s.webhookSealer.Seal([]byte(in.Secret))
	if err != nil {
		return fmt.Errorf("seal webhook secret: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE webhook_destination SET name = ?, url = ?, secret_sealed = ?, event_types = ?, min_severity = ?, enabled = ? WHERE id = ?`,
		in.Name, in.URL, sealed, eventTypes, minSeverity, in.Enabled, id)
	if err != nil {
		return fmt.Errorf("update webhook destination %d: %w", id, err)
	}
	return nil
}

// DeleteWebhookDestination removes a destination (its queued deliveries cascade away) or returns ErrWebhookNotFound.
func (s *Store) DeleteWebhookDestination(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM webhook_destination WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete webhook destination %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete webhook destination rows affected: %w", err)
	}
	if n == 0 {
		return ErrWebhookNotFound
	}
	return nil
}
