package service

import (
	"context"
	"time"
)

// Heartbeat advances the host's last-seen-ns on every /api/commands
// poll. Closure-typed so cmd/main can supply a heartbeat
// implementation (today: detection.api.RecordHostSeen) without
// response taking a hard dependency on detection.
//
// A non-nil error is logged at WARN by the service; a heartbeat
// failure does NOT fail the poll because the agent already got its
// commands and the next poll re-tries the upsert.
type Heartbeat func(ctx context.Context, hostID string, at time.Time) error
