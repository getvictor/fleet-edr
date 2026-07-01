package pipeline

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/fleetdm/edr/internal/secretseal"
	detapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/webhook"
)

// Delivery-worker defaults. These are intentionally conservative for the MVP; env-tunable knobs are a follow-up (issue #496).
const (
	defaultWebhookInterval    = 15 * time.Second
	defaultWebhookLease       = 60 * time.Second
	defaultWebhookBaseBackoff = 30 * time.Second
	defaultWebhookMaxBackoff  = time.Hour
	defaultWebhookMaxAttempts = 6
	defaultWebhookBatchSize   = 50
)

// webhookDeliveryStore is the outbox surface the worker drains. The mysql.Store satisfies it.
type webhookDeliveryStore interface {
	ClaimDueWebhookDeliveries(ctx context.Context, limit int, lease time.Duration) ([]detapi.WebhookDeliveryClaim, error)
	MarkWebhookDelivered(ctx context.Context, id int64, statusCode int) error
	RescheduleWebhookDelivery(ctx context.Context, id int64, nextAttempt time.Time, statusCode int, errMsg string) error
	MarkWebhookFailed(ctx context.Context, id int64, statusCode int, errMsg string) error
}

// webhookSender POSTs a signed payload and reports the HTTP status (0 on transport error). webhook.Client satisfies it.
type webhookSender interface {
	Deliver(ctx context.Context, url, id string, timestamp int64, body, secret []byte) (int, error)
}

// WebhookDeliveryRunner drains the webhook_delivery outbox: it claims due deliveries (leased via SKIP LOCKED so it scales across
// replicas without a leader lock), unseals each destination's secret, signs the payload, POSTs it, and records the outcome. A
// non-2xx or transport error is retried with exponential backoff until the attempt cap, after which the delivery is marked failed and
// surfaced to operators. Delivery is at-least-once; receivers dedup on the delivery id.
type WebhookDeliveryRunner struct {
	store       webhookDeliveryStore
	sealer      *secretseal.Sealer
	sender      webhookSender
	interval    time.Duration
	lease       time.Duration
	baseBackoff time.Duration
	maxBackoff  time.Duration
	maxAttempts int
	batchSize   int
	logger      *slog.Logger
	now         func() time.Time
}

// WebhookDeliveryOptions configures the runner; zero values fall back to the package defaults.
type WebhookDeliveryOptions struct {
	Sender      webhookSender
	Interval    time.Duration
	Lease       time.Duration
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	MaxAttempts int
	BatchSize   int
	Logger      *slog.Logger
	Now         func() time.Time
}

// NewWebhookDelivery builds the runner. store and sealer are required; the sender defaults to a hardened webhook.Client when not
// supplied (tests inject a fake).
func NewWebhookDelivery(store webhookDeliveryStore, sealer *secretseal.Sealer, opts WebhookDeliveryOptions) *WebhookDeliveryRunner {
	if store == nil {
		panic("pipeline.NewWebhookDelivery: store must not be nil")
	}
	if sealer == nil {
		panic("pipeline.NewWebhookDelivery: sealer must not be nil")
	}
	r := &WebhookDeliveryRunner{
		store:       store,
		sealer:      sealer,
		sender:      opts.Sender,
		interval:    opts.Interval,
		lease:       opts.Lease,
		baseBackoff: opts.BaseBackoff,
		maxBackoff:  opts.MaxBackoff,
		maxAttempts: opts.MaxAttempts,
		batchSize:   opts.BatchSize,
		logger:      opts.Logger,
		now:         opts.Now,
	}
	if r.interval <= 0 {
		r.interval = defaultWebhookInterval
	}
	if r.lease <= 0 {
		r.lease = defaultWebhookLease
	}
	if r.baseBackoff <= 0 {
		r.baseBackoff = defaultWebhookBaseBackoff
	}
	if r.maxBackoff <= 0 {
		r.maxBackoff = defaultWebhookMaxBackoff
	}
	if r.maxAttempts <= 0 {
		r.maxAttempts = defaultWebhookMaxAttempts
	}
	if r.batchSize <= 0 {
		r.batchSize = defaultWebhookBatchSize
	}
	if r.logger == nil {
		r.logger = slog.Default()
	}
	if r.now == nil {
		r.now = func() time.Time { return time.Now().UTC() }
	}
	if r.sender == nil {
		r.sender = webhook.NewClient(10*time.Second, 64*1024)
	}
	return r
}

// Loop drains the outbox on a ticker until ctx is cancelled.
func (r *WebhookDeliveryRunner) Loop(ctx context.Context) {
	runPeriodic(ctx, r.interval, r.logger, "webhook-delivery", r.Run)
}

// Run claims and processes one batch of due deliveries, returning how many it handled.
func (r *WebhookDeliveryRunner) Run(ctx context.Context) (int64, error) {
	claims, err := r.store.ClaimDueWebhookDeliveries(ctx, r.batchSize, r.lease)
	if err != nil {
		return 0, err
	}
	for _, c := range claims {
		if ctx.Err() != nil {
			break
		}
		r.deliver(ctx, c)
	}
	return int64(len(claims)), nil
}

func (r *WebhookDeliveryRunner) deliver(ctx context.Context, c detapi.WebhookDeliveryClaim) {
	secret, err := r.sealer.Open(c.SecretSealed)
	if err != nil {
		// An unopenable secret (root-key rotation, corruption) can never succeed: fail it terminally rather than retrying forever.
		r.fail(ctx, c.ID, 0, "unseal destination secret: "+err.Error())
		return
	}
	// Overlay the current attempt number onto the stored point-in-time envelope, then sign the exact bytes we send.
	var env webhook.Envelope
	if err := json.Unmarshal(c.Payload, &env); err != nil {
		r.fail(ctx, c.ID, 0, "decode stored payload: "+err.Error())
		return
	}
	env.DeliveryAttempt = c.Attempt
	body, err := json.Marshal(env)
	if err != nil {
		r.fail(ctx, c.ID, 0, "encode payload: "+err.Error())
		return
	}

	code, sendErr := r.sender.Deliver(ctx, c.URL, c.PublicID, r.now().Unix(), body, secret)
	switch {
	case sendErr == nil && code >= 200 && code < 300:
		if err := r.store.MarkWebhookDelivered(ctx, c.ID, code); err != nil {
			r.logger.ErrorContext(ctx, "mark webhook delivered", "id", c.ID, "err", err)
		}
	case c.Attempt >= r.maxAttempts:
		r.fail(ctx, c.ID, code, sendErrString(sendErr))
	default:
		next := r.now().Add(r.backoff(c.Attempt))
		if err := r.store.RescheduleWebhookDelivery(ctx, c.ID, next, code, sendErrString(sendErr)); err != nil {
			r.logger.ErrorContext(ctx, "reschedule webhook delivery", "id", c.ID, "err", err)
		}
	}
}

func (r *WebhookDeliveryRunner) fail(ctx context.Context, id int64, code int, msg string) {
	if err := r.store.MarkWebhookFailed(ctx, id, code, msg); err != nil {
		r.logger.ErrorContext(ctx, "mark webhook failed", "id", id, "err", err)
	}
}

// backoff returns base * 2^(attempt-1), capped at maxBackoff. attempt is the just-completed attempt number (>= 1).
func (r *WebhookDeliveryRunner) backoff(attempt int) time.Duration {
	d := r.baseBackoff
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= r.maxBackoff {
			return r.maxBackoff
		}
	}
	if d > r.maxBackoff {
		return r.maxBackoff
	}
	return d
}

func sendErrString(err error) string {
	if err != nil {
		return err.Error()
	}
	return "non-2xx response"
}
