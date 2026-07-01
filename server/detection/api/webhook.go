package api

import "time"

// WebhookDestination is an operator-managed outbound webhook endpoint (issue #496). The signing secret is sealed at rest and is never
// carried on this read model: SecretSet reports only whether one is stored. EventTypes is decoded from the persisted SET column.
type WebhookDestination struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	EventTypes  []string  `json:"event_types"`
	MinSeverity string    `json:"min_severity"`
	Enabled     bool      `json:"enabled"`
	SecretSet   bool      `json:"secret_set"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// WebhookDestinationInput is the operator-supplied create/update payload. Secret is the plaintext signing secret: the store seals it
// before persistence and never returns it. On update an empty Secret means "keep the stored secret" so the operator can edit other
// fields without re-entering it.
type WebhookDestinationInput struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	EventTypes  []string `json:"event_types"`
	MinSeverity string   `json:"min_severity"`
	Enabled     bool     `json:"enabled"`
	Secret      string   `json:"secret,omitempty"`
}

// Webhook event types a destination can subscribe to. These are the values persisted in the destination event_types SET and echoed in
// the delivery payload envelope.
const (
	WebhookEventAlertCreated       = "alert.created"
	WebhookEventAlertStatusChanged = "alert.status_changed"
)

// WebhookDeliveryStatus is the outbox row lifecycle: pending until a 2xx or the retry cap, then delivered or failed.
type WebhookDeliveryStatus string

const (
	WebhookDeliveryPending   WebhookDeliveryStatus = "pending"
	WebhookDeliveryDelivered WebhookDeliveryStatus = "delivered"
	WebhookDeliveryFailed    WebhookDeliveryStatus = "failed"
)
