package bootstrap_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/observability/tracing"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	obsbootstrap "github.com/fleetdm/edr/server/observability/bootstrap"
	"github.com/fleetdm/edr/server/testdb"
)

type allowAuthZ struct{}

func (allowAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	return api.Decision{Allow: true, Reason: "granted"}, nil
}

type noopAudit struct{}

func (noopAudit) Record(context.Context, api.AuditEvent) error { return nil }

func TestNew_requiresDeps(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)

	_, err := obsbootstrap.New(obsbootstrap.Deps{AuthZ: allowAuthZ{}, Audit: noopAudit{}})
	require.Error(t, err, "nil DB must be rejected")

	_, err = obsbootstrap.New(obsbootstrap.Deps{DB: db, Audit: noopAudit{}})
	require.Error(t, err, "nil AuthZ must be rejected")

	_, err = obsbootstrap.New(obsbootstrap.Deps{DB: db, AuthZ: allowAuthZ{}})
	require.Error(t, err, "nil Audit must be rejected")
}

func TestObservability_applySchemaThenReadAndRegister(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)
	o, err := obsbootstrap.New(obsbootstrap.Deps{DB: db, AuthZ: allowAuthZ{}, Audit: noopAudit{}})
	require.NoError(t, err)
	require.NoError(t, o.ApplySchema(t.Context()))

	// After schema apply, the reader the poller consumes returns the seeded defaults.
	got, err := o.TraceSamplerSettingsReader().GetTraceSamplerSettings(t.Context())
	require.NoError(t, err)
	assert.InDelta(t, tracing.DefaultHighVolumeRatio, got.HighVolumeRatio, 1e-9)
	assert.InDelta(t, tracing.DefaultStandardRatio, got.StandardRatio, 1e-9)

	// The admin routes mount on the operator mux.
	rec := httpserver.NewRecordingRouter(http.NewServeMux())
	o.RegisterAuthedRoutes(rec)
	patterns := rec.Patterns()
	assert.Contains(t, patterns, "GET /api/settings/tracing")
	assert.Contains(t, patterns, "PATCH /api/settings/tracing")
}

func TestApplySchema_nilDBRejected(t *testing.T) {
	t.Parallel()
	require.Error(t, obsbootstrap.ApplySchema(t.Context(), nil))
}
