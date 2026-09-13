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

// activeEnrollmentsStub answers only ActiveEnrollments; every other endpoint method is outside the adapter under test.
type activeEnrollmentsStub struct {
	endpointapi.Service
	enrollments []endpointapi.ActiveEnrollment
}

func (s activeEnrollmentsStub) ActiveEnrollments(context.Context) ([]endpointapi.ActiveEnrollment, error) {
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

func TestActiveEnrollmentsFromEndpoint_CarriesHostAndEnrollmentTime(t *testing.T) {
	t.Parallel()
	enrolledAt := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	list := activeEnrollmentsFromEndpoint(activeEnrollmentsStub{enrollments: []endpointapi.ActiveEnrollment{
		{HostID: "host-a", EnrolledAt: enrolledAt},
		{HostID: "host-b", EnrolledAt: enrolledAt.Add(time.Hour)},
	}})

	got, err := list(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []rulesapi.WatchedPathEnrollment{
		{HostID: "host-a", EnrolledAt: enrolledAt},
		{HostID: "host-b", EnrolledAt: enrolledAt.Add(time.Hour)},
	}, got)
}

func TestLatestCommandsFromResponse_CarriesTheFieldsTheCatchUpReads(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	completed := created.Add(time.Minute)
	stub := &latestOfTypeStub{latest: map[string]responseapi.Command{
		"host-a": {ID: 7, HostID: "host-a", Payload: json.RawMessage(`{"version":2}`), Status: responseapi.StatusFailed,
			CreatedAt: created, CompletedAt: &completed},
		"host-b": {ID: 8, HostID: "host-b", Payload: json.RawMessage(`{"version":2}`), Status: responseapi.StatusPending, CreatedAt: created},
	}}

	got, err := latestCommandsFromResponse(stub)(t.Context(), rulesapi.CommandTypeSetWatchedPaths, []string{"host-a", "host-b"})
	require.NoError(t, err)
	assert.Equal(t, rulesapi.CommandTypeSetWatchedPaths, stub.gotType)
	assert.Equal(t, []string{"host-a", "host-b"}, stub.gotHosts)
	assert.Equal(t, map[string]rulesapi.WatchedPathCommand{
		"host-a": {Payload: []byte(`{"version":2}`), Status: "failed", CreatedAt: created, CompletedAt: completed},
		"host-b": {Payload: []byte(`{"version":2}`), Status: "pending", CreatedAt: created},
	}, got)
}
