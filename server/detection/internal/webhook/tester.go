package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fleetdm/edr/internal/secretseal"
	detapi "github.com/fleetdm/edr/server/detection/api"
)

// Tester sends an operator-initiated test delivery to a destination: it signs and POSTs a synthetic `webhook.test` payload through the
// same SSRF-hardened client and signing path as a real delivery, so a successful test proves the URL, the secret, and the egress
// guards all work end to end. It creates no alert and enqueues nothing. It does not hold the store (which imports this package for URL
// validation); the caller loads the destination URL + sealed secret and passes them in, keeping the dependency acyclic.
type Tester struct {
	client         *Client
	sealer         *secretseal.Sealer
	consoleBaseURL string
	now            func() time.Time
}

// NewTester builds a test-sender from a delivery client and the secret sealer. consoleBaseURL is echoed in the test payload's link.
func NewTester(client *Client, sealer *secretseal.Sealer, consoleBaseURL string) *Tester {
	return &Tester{client: client, sealer: sealer, consoleBaseURL: consoleBaseURL, now: func() time.Time { return time.Now().UTC() }}
}

// SendTest unseals the destination secret, builds and signs a synthetic test envelope, and POSTs it to url, returning the HTTP status
// code (0 on a transport or SSRF-block error) and any error. The unsealed secret is zeroed before returning.
func (t *Tester) SendTest(ctx context.Context, url string, sealed []byte) (int, error) {
	secret, err := t.sealer.Open(sealed)
	if err != nil {
		return 0, fmt.Errorf("unseal destination secret: %w", err)
	}
	defer clear(secret)

	id := uuid.NewString()
	env := Build(BuildParams{
		EventID:    id,
		EventType:  EventTest,
		OccurredAt: t.now(),
		Attempt:    1,
		Alert: detapi.Alert{
			Title:       "Fleet EDR webhook test",
			Description: "This is a test delivery triggered from the console; no alert was created.",
			Severity:    detapi.SeverityLow,
			Source:      detapi.AlertSourceDetection,
			Status:      detapi.AlertStatusOpen,
		},
		ConsoleBaseURL: t.consoleBaseURL,
	})
	body, err := json.Marshal(env)
	if err != nil {
		return 0, fmt.Errorf("encode test payload: %w", err)
	}
	return t.client.Deliver(ctx, url, id, t.now().Unix(), body, secret)
}
