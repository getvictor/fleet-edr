package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	responseapi "github.com/fleetdm/edr/server/response/api"
)

// enrollmentStub answers Get and ActiveEnrollments; every other endpoint method is outside the adapters under test.
type enrollmentStub struct {
	endpointapi.Service
	byHost map[string]*endpointapi.Enrollment
	getErr error
	active []endpointapi.ActiveEnrollment
}

func (s enrollmentStub) Get(_ context.Context, hostID string) (*endpointapi.Enrollment, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	e, ok := s.byHost[hostID]
	if !ok {
		return nil, endpointapi.ErrNotFound
	}
	return e, nil
}

func (s enrollmentStub) ActiveEnrollments(context.Context) ([]endpointapi.ActiveEnrollment, error) {
	return s.active, nil
}

func TestHostEnrolledFromEndpoint(t *testing.T) {
	t.Parallel()
	revokedAt := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	stub := enrollmentStub{byHost: map[string]*endpointapi.Enrollment{
		"active": {HostID: "active"}, "revoked": {HostID: "revoked", RevokedAt: &revokedAt},
	}}
	enrolled := hostEnrolledFromEndpoint(stub)
	cases := []struct {
		name, host string
		want       bool
	}{
		{"an active enrollment", "active", true},
		{"a revoked enrollment", "revoked", false},
		{"no enrollment", "unknown", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := enrolled(t.Context(), tc.host)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	t.Run("a lookup failure", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		_, err := hostEnrolledFromEndpoint(enrollmentStub{getErr: boom})(t.Context(), "active")
		require.ErrorIs(t, err, boom)
	})
}

func TestContainmentEnrollmentsFromEndpoint_CarriesHostAndEnrollmentTime(t *testing.T) {
	t.Parallel()
	enrolledAt := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	got, err := containmentEnrollmentsFromEndpoint(enrollmentStub{active: []endpointapi.ActiveEnrollment{
		{HostID: "host-a", EnrolledAt: enrolledAt},
	}})(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []responseapi.HostEnrollment{{HostID: "host-a", EnrolledAt: enrolledAt}}, got)
}
