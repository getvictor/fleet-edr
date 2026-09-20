// Package arch_test gates the architectural invariants every PR must preserve. shutdown_grace_test holds two numbers in step that
// live in different file formats and would otherwise drift silently: how long the server needs to shut down, and how long the
// deployments this project ships actually give it.
//
// The drain exists for the load balancer, not the server: the replica reports itself unready and keeps serving for the window so
// the LB pulls it from rotation before the listener closes. A deployment that kills the process part-way through does not get a
// faster shutdown, it gets none of that, plus severed in-flight requests, plus no final telemetry flush. Docker's default grace
// period is 10 seconds against a 30-second drain, so every compose here was doing exactly that (issue #1127).
//
// Checked by a test rather than by review because raising the drain is a Go change, the allowance is a YAML change, and nothing
// reads both. The failure mode is invisible until a replica is next rolled.
package arch_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/fleetdm/edr/server/bootstrap"
	serverconfig "github.com/fleetdm/edr/server/config"
	"github.com/fleetdm/edr/server/httpserver"
)

// serverImage is how a compose service that runs the EDR server is recognised. A service running something else has no shutdown
// of ours to wait for.
const serverImage = "ghcr.io/getvictor/fleet-edr-server"

// composeGlobs are where this project keeps compose files. Every one of them is read and any service running the server image is
// checked, rather than working from a list of known files: a new stack must not be able to arrive with no allowance and no
// failure, and a list is exactly what would let it. Files that run something else are skipped by the image check, so the glob
// being broad costs nothing.
var composeGlobs = []string{"docker-compose*.yml", "packaging/docker-compose*.yml"}

// minimumComposeFilesRunningTheServer guards the discovery itself. A glob that stopped matching, or an image name that changed,
// would otherwise leave this test passing while checking nothing at all, which is the failure mode a discovering test has and a
// listing one does not.
const minimumComposeFilesRunningTheServer = 4

// composeFilesRunningTheServer finds every compose file in the repository, relative to the repo root.
func composeFilesRunningTheServer(t *testing.T) []string {
	t.Helper()
	var found []string
	for _, glob := range composeGlobs {
		matches, err := filepath.Glob(filepath.Join("..", "..", glob))
		require.NoError(t, err)
		found = append(found, matches...)
	}
	sort.Strings(found)
	return found
}

// composeDoc is the part of a compose file this reads: its services, and the anchor block the multi-replica stack shares between
// its replicas, which carries the settings rather than the services themselves.
type composeDoc struct {
	Services map[string]composeService `json:"services"`
	XServer  *composeService           `json:"x-server"`
}

type composeService struct {
	Image string `json:"image"`
	// StopGracePeriod is how long the runtime waits after SIGTERM before SIGKILL. Absent means Docker's default of 10s.
	StopGracePeriod string `json:"stop_grace_period"`
}

// shutdownNeeds is the longest a graceful shutdown can take, as the sum of EVERY bounded stage, in the order they run: the drain
// window, the deadline for in-flight requests, the two loop joins cmd/main performs after serving stops, and the telemetry flush.
//
// Summing all of them is the point. Counting only the drain and the in-flight deadline gives 45s and looks reasonable, but the
// stages after it add 20s more, so a deployment sized against the short answer is killed during the flush rather than during the
// drain: later, and just as fatal to the thing it was meant to allow.
//
// Every term is read from the constant that governs it, so raising any one of them moves this and fails the deployments that no
// longer outlast it. That is the whole mechanism: five numbers in four packages, and nothing else reads them together.
//
// The drain term is the compiled DEFAULT. An operator who raises EDR_SHUTDOWN_DRAIN has to raise their allowance to match, which
// no test here can see and the operator documentation therefore says.
func shutdownNeeds() time.Duration {
	return serverconfig.DefaultShutdownDrain() +
		httpserver.ShutdownTimeout +
		httpserver.RulesJoinTimeout +
		httpserver.ResponseJoinTimeout +
		bootstrap.OTelFlushTimeout
}

// spec:server-availability/deployments-allow-the-server-to-finish-shutting-down/a-shipped-deployment-outlasts-the-shutdown-it-triggers
func TestShippedDeploymentsOutlastTheServersShutdown(t *testing.T) {
	t.Parallel()
	needs := shutdownNeeds()

	filesRunningTheServer := 0
	for _, path := range composeFilesRunningTheServer(t) {
		//nolint:gosec // G304: the path came from a glob over this repository, not from any input.
		raw, err := os.ReadFile(path)
		require.NoError(t, err)

		var doc composeDoc
		require.NoError(t, yaml.Unmarshal(raw, &doc), "%s is not readable as a compose file", path)

		runs := false
		for name, svc := range doc.Services {
			if !runsTheServer(svc, doc) {
				continue
			}
			runs = true
			assertOutlasts(t, filepath.Base(path)+" service "+name, gracePeriodFor(svc, doc), needs)
		}
		if runs {
			filesRunningTheServer++
		}
	}
	require.GreaterOrEqual(t, filesRunningTheServer, minimumComposeFilesRunningTheServer,
		"found %d compose files running the server; the discovery or the image name has drifted and this test is checking "+
			"less than it thinks", filesRunningTheServer)
}

// runsTheServer reports whether a service runs the EDR server, directly or by inheriting the shared anchor.
func runsTheServer(svc composeService, doc composeDoc) bool {
	if svc.Image == "" && doc.XServer != nil {
		// A service that merges the anchor and overrides nothing decodes with an empty image: the anchor is what runs the server.
		return hasServerImage(*doc.XServer)
	}
	return hasServerImage(svc)
}

func hasServerImage(svc composeService) bool {
	return len(svc.Image) >= len(serverImage) && svc.Image[:len(serverImage)] == serverImage
}

// gracePeriodFor is the service's own allowance, or the anchor's when it inherits one.
func gracePeriodFor(svc composeService, doc composeDoc) string {
	if svc.StopGracePeriod == "" && doc.XServer != nil {
		return doc.XServer.StopGracePeriod
	}
	return svc.StopGracePeriod
}

// outlasts reports whether an allowance gives a graceful shutdown room to finish, and says why not when it does not.
//
// Separated from the assertion so the rule itself can be exercised directly: what has to hold is not only that today's files
// pass, but that a file which stopped allowing enough would be caught.
func outlasts(grace string, needs time.Duration) (bool, string) {
	if grace == "" {
		return false, fmt.Sprintf("declares no stop_grace_period, so the runtime kills the server after its own default "+
			"(10s in Docker) while a graceful shutdown needs %s", needs)
	}
	allowed, err := time.ParseDuration(grace)
	if err != nil {
		return false, fmt.Sprintf("has an unparseable stop_grace_period %q", grace)
	}
	if allowed <= needs {
		return false, fmt.Sprintf("allows %s, which does not outlast the %s a graceful stop needs: drain %s, in-flight "+
			"deadline %s, rules join %s, response join %s, telemetry flush %s. The server would be killed part-way through, "+
			"and the load balancer would never see the drain it is watching for",
			allowed, needs, serverconfig.DefaultShutdownDrain(), httpserver.ShutdownTimeout,
			httpserver.RulesJoinTimeout, httpserver.ResponseJoinTimeout, bootstrap.OTelFlushTimeout)
	}
	return true, ""
}

func assertOutlasts(t *testing.T, where, grace string, needs time.Duration) {
	t.Helper()
	ok, why := outlasts(grace, needs)
	assert.True(t, ok, "%s %s", where, why)
}

// The rule has to catch a deployment that stops allowing enough, which is what happens when the drain is raised and the compose
// files are not. Driven directly, because the committed files all pass by construction and a test that only ever sees passing
// input proves nothing about the failing case.
//
// spec:server-availability/deployments-allow-the-server-to-finish-shutting-down/raising-the-drain-without-raising-the-allowance-is-caught
func TestTooLittleGraceIsCaught(t *testing.T) {
	t.Parallel()
	const needs = 45 * time.Second
	cases := []struct {
		desc   string
		grace  string
		wantOK bool
	}{
		{desc: "nothing declared, so the runtime's own default applies", grace: "", wantOK: false},
		{desc: "Docker's default, which is what this exists to catch", grace: "10s", wantOK: false},
		{desc: "shorter than the drain alone", grace: "20s", wantOK: false},
		{desc: "exactly what is needed, which leaves no room for the window to end in", grace: "45s", wantOK: false},
		{desc: "unparseable", grace: "a minute please", wantOK: false},
		{desc: "longer than needed", grace: "60s", wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			ok, why := outlasts(tc.grace, needs)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Empty(t, why)
				return
			}
			assert.NotEmpty(t, why, "a refusal has to say what is wrong, since the reader is looking at YAML and Go at once")
		})
	}
}

// The budget has to count the stages that run AFTER serving stops, and nothing else here can notice if it stops doing so: the
// allowances are deliberately generous, so a budget that shrank would still pass the comparison above. That is exactly the
// mistake this change was filed to fix, made once already: 45 seconds looks like the whole shutdown and is two thirds of it.
func TestTheBudgetCountsTheStagesAfterServing(t *testing.T) {
	t.Parallel()
	serving := serverconfig.DefaultShutdownDrain() + httpserver.ShutdownTimeout

	assert.Greater(t, shutdownNeeds(), serving,
		"the budget must include the loop joins and the telemetry flush, which run after the listener closes; counting only "+
			"the serving stages is what left every shipped deployment short")
}
