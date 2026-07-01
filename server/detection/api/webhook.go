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

// WebhookDeliveryClaim is one outbox row leased to the delivery worker: enough to sign and POST it. Payload is the stored envelope
// (the worker overlays the current attempt number before signing); SecretSealed is the destination's sealed signing secret, opened by
// the worker. Attempt is the post-increment attempt number for this send.
type WebhookDeliveryClaim struct {
	ID           int64
	PublicID     string
	Attempt      int
	URL          string
	Payload      []byte
	SecretSealed []byte
}

// WebhookDelivery is the operator-facing delivery-status read model: the outcome of one queued delivery, surfaced so an operator can
// confirm a destination is healthy. It does not carry the payload or any secret.
type WebhookDelivery struct {
	ID             int64                 `json:"id"`
	DestinationID  int64                 `json:"destination_id"`
	EventType      string                `json:"event_type"`
	Status         WebhookDeliveryStatus `json:"status"`
	Attempt        int                   `json:"attempt"`
	LastStatusCode *int                  `json:"last_status_code,omitempty"`
	LastError      string                `json:"last_error,omitempty"`
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
	NextAttemptAt  time.Time             `json:"next_attempt_at"`
}

// WebhookDeliveryStatus is the outbox row lifecycle: pending until a 2xx or the retry cap, then delivered or failed.
type WebhookDeliveryStatus string

const (
	WebhookDeliveryPending   WebhookDeliveryStatus = "pending"
	WebhookDeliveryDelivered WebhookDeliveryStatus = "delivered"
	WebhookDeliveryFailed    WebhookDeliveryStatus = "failed"
)
