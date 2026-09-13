package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	responseapi "github.com/fleetdm/edr/server/response/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// enrollmentListStub answers only List; every other endpoint method is outside the adapter under test.
type enrollmentListStub struct {
	endpointapi.Service
	enrollments []endpointapi.Enrollment
}

func (s enrollmentListStub) List(context.Context) ([]endpointapi.Enrollment, error) {
	return s.enrollments, nil
}

// latestOfTypeStub answers only LatestOfType.
type latestOfTypeStub struct {
	responseapi.Service
	gotType  string
	gotHosts []string
	latest   map[string]responseapi.Command
}

func (s *latestOfTypeStub) LatestOfType(_ context.Context, commandType string, hostIDs []string) (map[string]responseapi.Command, error) {
	s.gotType, s.gotHosts = commandType, hostIDs
	return s.latest, nil
}

// The catch-up is fed active enrollments only: a revoked host has no valid token and must not be sent the set.
func TestActiveEnrollmentsFromEndpoint_DropsRevokedEnrollments(t *testing.T) {
	t.Parallel()
	enrolledAt := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	revokedAt := enrolledAt.Add(time.Hour)
	list := activeEnrollmentsFromEndpoint(enrollmentListStub{enrollments: []endpointapi.Enrollment{
		{HostID: "active", EnrolledAt: enrolledAt},
		{HostID: "revoked", EnrolledAt: enrolledAt, RevokedAt: &revokedAt},
	}})

	got, err := list(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []rulesapi.WatchedPathEnrollment{{HostID: "active", EnrolledAt: enrolledAt}}, got)
}

func TestLatestCommandsFromResponse_CarriesTheFieldsTheCatchUpReads(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	completed := created.Add(time.Minute)
	stub := &latestOfTypeStub{latest: map[string]responseapi.Command{
		"host-a": {ID: 7, HostID: "host-a", Payload: json.RawMessage(`{"version":2}`), Status: responseapi.StatusFailed,
			CreatedAt: created, CompletedAt: &completed},
	}}

	got, err := latestCommandsFromResponse(stub)(t.Context(), rulesapi.CommandTypeSetWatchedPaths, []string{"host-a", "host-b"})
	require.NoError(t, err)
	assert.Equal(t, rulesapi.CommandTypeSetWatchedPaths, stub.gotType)
	assert.Equal(t, []string{"host-a", "host-b"}, stub.gotHosts)
	assert.Equal(t, map[string]rulesapi.WatchedPathCommand{
		"host-a": {Payload: []byte(`{"version":2}`), Status: "failed", CreatedAt: created, CompletedAt: &completed},
	}, got)
}
