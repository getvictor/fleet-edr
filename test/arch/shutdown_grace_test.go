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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	serverconfig "github.com/fleetdm/edr/server/config"
	"github.com/fleetdm/edr/server/httpserver"
)

// serverImage is how a compose service that runs the EDR server is recognised. A service running something else has no shutdown
// of ours to wait for.
const serverImage = "ghcr.io/getvictor/fleet-edr-server"

// composeFiles are every deployment artefact in this repository that runs the server, relative to the repo root. Listed rather
// than discovered so that adding a stack is a deliberate act that includes deciding this: a glob would let a new compose file
// arrive with no allowance and no failure.
var composeFiles = []string{
	"docker-compose.prod.yml",
	"docker-compose.quickstart.yml",
	"docker-compose.demo.yml",
	"packaging/docker-compose-multi-replica.yml",
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

// shutdownNeeds is the longest a graceful shutdown can take: the drain window the operator configures, then the deadline for
// in-flight requests. Read from the server's own constants so this cannot restate them wrongly.
func shutdownNeeds() time.Duration {
	return serverconfig.DefaultShutdownDrain() + httpserver.ShutdownTimeout
}

// spec:server-availability/deployments-allow-the-server-to-finish-shutting-down/a-shipped-deployment-outlasts-the-shutdown-it-triggers
func TestShippedDeploymentsOutlastTheServersShutdown(t *testing.T) {
	t.Parallel()
	needs := shutdownNeeds()

	for _, file := range composeFiles {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			//nolint:gosec // G304: the path comes from composeFiles above, a hardcoded list, not from any input.
			raw, err := os.ReadFile(filepath.Join("..", "..", file))
			require.NoError(t, err, "every listed deployment must exist; a renamed one is a drift this test exists to catch")

			var doc composeDoc
			require.NoError(t, yaml.Unmarshal(raw, &doc))

			checked := 0
			for name, svc := range doc.Services {
				if !runsTheServer(svc, doc) {
					continue
				}
				checked++
				assertOutlasts(t, file+" service "+name, gracePeriodFor(svc, doc), needs)
			}
			require.Positive(t, checked, "this file is listed as running the server and no service in it does")
		})
	}
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
		return false, fmt.Sprintf("allows %s, which does not outlast the %s a graceful shutdown needs (drain %s plus "+
			"shutdown deadline %s); the server would be killed part-way through the drain the load balancer is watching",
			allowed, needs, serverconfig.DefaultShutdownDrain(), httpserver.ShutdownTimeout)
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
