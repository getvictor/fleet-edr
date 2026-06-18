//go:build integration && (!darwin || !cgo)

// Package efficacy_test is the UAT plan L6 detection-efficacy harness (M10).
//
// What this layer proves
// ----------------------
// Every attack scenario under corpus/T<MITRE-id>-<slug>/ fires the catalog
// rule named in its expected.yaml within the per-scenario SLA, and every
// benign scenario under noise/ fires ZERO catalog rules. Two aggregate
// gates back this up:
//
//	detection rate = passed_attacks / total_attacks  must stay >= 95%
//	false positive rate = (noise scenarios that produced alerts) / total_noise  must stay <= 1%
//
// Per UAT plan section L6 + docs/testing-strategy.md.
//
// How
// ---
// One in-process Stack (test/integration.Setup) shared across scenarios.
// Each scenario enrols a unique host via POST /api/enroll, gets a host
// token, POSTs its event timeline directly to /api/events via the M3
// fakeagent's PostDirect (no headless agent in the loop: the queue +
// uploader path is already L3-covered by M4, and L6 cares specifically
// about rule firings). The runner polls the detection service's ListAlerts
// for the expected rule_id; for noise scenarios it asserts the host's
// total alert count stays zero.
//
// Build tag pairing matches the rest of the integration suite:
//
//	integration               -- the existing test/integration gate.
//	!darwin || !cgo           -- the receiver-stub gate; this test
//	                              doesn't link the receiver but mirrors the
//	                              constraint so CI runs it on ubuntu-latest
//	                              under CGO_ENABLED=0 in the dedicated
//	                              `Detection efficacy` workflow
//	                              (.github/workflows/efficacy.yml). The
//	                              per-PR server-test job does NOT pick this
//	                              up. L6 runs on the nightly cadence, not
//	                              every PR.
package efficacy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/test/fakeagent"
	"github.com/fleetdm/edr/test/integration"
)

const (
	// detectionRateGate + fpRateGate are the L6 contract numbers from
	// docs/testing-strategy.md. Tightening either is a deliberate doc
	// edit, not a silent code change.
	detectionRateGate = 0.95
	fpRateGate        = 0.01

	// pollInterval and pollMax bound the per-scenario rule-fire wait.
	// pollMax is overridden per-scenario from expected.yaml's
	// within_seconds; this is the default ceiling for noise scenarios
	// (which simply need to confirm ZERO alerts after a settle window).
	pollInterval = 100 * time.Millisecond
	pollMax      = 30 * time.Second

	// noiseSettle is how long the runner waits after the last POST for a
	// noise scenario before declaring no alerts fired. Short because the
	// detection processor runs every ~250ms; 2s is generous.
	noiseSettle = 2 * time.Second
)

// expectedAssertion is the subset of expected.yaml the runner consumes.
// The full schema is documented in test/efficacy/README.md.
type expectedAssertion struct {
	ScenarioID    string `json:"scenario_id"`
	Mitre         string `json:"mitre,omitempty"`
	WithinSeconds int    `json:"within_seconds"`
	Rules         []struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Expect   string `json:"expect"`
	} `json:"rules"`
}

// scenarioEntry pairs the loaded fakeagent.Scenario with its expected
// outcome and the technique directory name (used for the t.Run subtest
// name + the per-scenario report line).
type scenarioEntry struct {
	Name     string
	Scenario *fakeagent.Scenario
	Expected expectedAssertion
}

// result records the outcome of one scenario for the aggregate gate.
type result struct {
	Name   string
	Kind   string // "attack" or "noise"
	Passed bool
	Reason string
}

func TestL6_DetectionEfficacy(t *testing.T) {
	stack := integration.Setup(t)

	attacks := loadCorpus(t, "corpus", false)
	noise := loadCorpus(t, "noise", true)

	require.NotEmpty(t, attacks, "no attack scenarios discovered under corpus/")
	require.NotEmpty(t, noise, "no noise scenarios discovered under noise/")

	var (
		results       []result
		appendResultM = func(r result) { results = append(results, r) }
	)

	for _, attack := range attacks {
		t.Run("attack/"+attack.Name, func(t *testing.T) {
			appendResultM(runAttack(t, stack, attack))
		})
	}

	for _, ns := range noise {
		t.Run("noise/"+ns.Name, func(t *testing.T) {
			appendResultM(runNoise(t, stack, ns))
		})
	}

	// Aggregate gates. Computed AFTER every subtest so a per-scenario
	// failure shows up in the test report at its own line AND in the
	// aggregate line below, so the operator can distinguish "one
	// scenario regressed" from "the whole layer is broken."
	var attackTotal, attackPassed, noiseTotal, noiseFalse int
	for _, r := range results {
		switch r.Kind {
		case "attack":
			attackTotal++
			if r.Passed {
				attackPassed++
			}
		case "noise":
			noiseTotal++
			if !r.Passed {
				noiseFalse++
			}
		}
	}
	detRate := float64(attackPassed) / float64(attackTotal)
	fpRate := float64(noiseFalse) / float64(noiseTotal)
	t.Logf("L6 aggregate: detection_rate=%.1f%% (%d/%d) fp_rate=%.1f%% (%d/%d)",
		detRate*100, attackPassed, attackTotal,
		fpRate*100, noiseFalse, noiseTotal)
	if detRate < detectionRateGate {
		t.Errorf("detection rate %.1f%% < %.0f%% gate (%d / %d attack scenarios passed)",
			detRate*100, detectionRateGate*100, attackPassed, attackTotal)
	}
	if fpRate > fpRateGate {
		t.Errorf("false-positive rate %.1f%% > %.1f%% gate (%d / %d noise scenarios produced alerts)",
			fpRate*100, fpRateGate*100, noiseFalse, noiseTotal)
	}
}

// loadCorpus walks <root>/ (corpus/ or noise/). For corpus the layout is
// per-technique subdirs each containing scenario.yaml + expected.yaml;
// for noise it's flat *.yaml + a single noise/expected.yaml that applies
// to all of them. The function dies (t.Fatal) on any malformed entry --
// L6's whole point is "rules fire on real attacks" and a typo'd YAML
// silently dropping a scenario would be a quiet way to weaken the gate.
func loadCorpus(t *testing.T, root string, isNoise bool) []scenarioEntry {
	t.Helper()

	if isNoise {
		return loadNoiseCorpus(t, root)
	}

	// os.ReadDir returns entries sorted by filename per the Go docs; no
	// explicit sort needed.
	entries, err := os.ReadDir(root)
	require.NoErrorf(t, err, "read %s", root)

	out := make([]scenarioEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		scenario, err := fakeagent.LoadScenario(filepath.Join(dir, "scenario.yaml"))
		require.NoErrorf(t, err, "load %s/scenario.yaml", dir)
		expected, err := loadExpected(filepath.Join(dir, "expected.yaml"))
		require.NoErrorf(t, err, "load %s/expected.yaml", dir)
		out = append(out, scenarioEntry{
			Name:     e.Name(),
			Scenario: scenario,
			Expected: expected,
		})
	}
	return out
}

func loadNoiseCorpus(t *testing.T, root string) []scenarioEntry {
	t.Helper()
	expected, err := loadExpected(filepath.Join(root, "expected.yaml"))
	require.NoErrorf(t, err, "load %s/expected.yaml", root)

	// os.ReadDir is sorted; no explicit sort needed (same as loadCorpus).
	entries, err := os.ReadDir(root)
	require.NoErrorf(t, err, "read %s", root)

	out := make([]scenarioEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" || e.Name() == "expected.yaml" {
			continue
		}
		scenario, err := fakeagent.LoadScenario(filepath.Join(root, e.Name()))
		require.NoErrorf(t, err, "load %s/%s", root, e.Name())
		out = append(out, scenarioEntry{
			Name:     strings.TrimSuffix(e.Name(), ".yaml"),
			Scenario: scenario,
			Expected: expected,
		})
	}
	return out
}

func loadExpected(path string) (expectedAssertion, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return expectedAssertion{}, fmt.Errorf("read %s: %w", path, err)
	}
	var exp expectedAssertion
	if err := yaml.Unmarshal(raw, &exp); err != nil {
		return expectedAssertion{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return exp, nil
}

// runAttack drives one attack scenario and returns whether EVERY expected
// rule in the scenario's expected.yaml fired within the SLA. Errors in the
// wiring path (enroll failure, POST 5xx, etc.) produce t.Errorf + a failed
// result so they show up in BOTH the per-scenario subtest report AND the
// aggregate gate computation; critically the function NEVER calls
// t.FailNow / require.NoError, because that would abort the subtest before
// the parent test could append the result to `results` and the scenario
// would silently drop out of the aggregate denominator.
func runAttack(t *testing.T, stack *integration.Stack, entry scenarioEntry) result {
	t.Helper()
	res := result{Name: entry.Name, Kind: "attack"}

	hostID := entry.Scenario.Host.ID
	ctx := t.Context()
	token, err := enroll(ctx, stack, hostID, entry.Name)
	if err != nil {
		t.Errorf("enroll: %v", err)
		res.Reason = err.Error()
		return res
	}

	if err := entry.Scenario.PostDirect(ctx, stack.Server.URL, token); err != nil {
		t.Errorf("PostDirect: %v", err)
		res.Reason = err.Error()
		return res
	}

	if len(entry.Expected.Rules) == 0 {
		// An attack scenario with no rules in expected.yaml is a config
		// error: the harness can't evaluate it.
		t.Errorf("attack scenario %s has no rules in expected.yaml", entry.Name)
		res.Reason = "expected.yaml has no rules"
		return res
	}

	deadline := pollMax
	if entry.Expected.WithinSeconds > 0 {
		deadline = time.Duration(entry.Expected.WithinSeconds) * time.Second
	}

	// Iterate every expected rule; the scenario passes only if all of them
	// fire. Multi-rule expectations (a scenario tripping more than one
	// catalog rule) would otherwise have N-1 silently-ignored assertions.
	res.Passed = true
	for _, expected := range entry.Expected.Rules {
		ok, err := waitForAlert(ctx, stack, hostID, expected.RuleID, expected.Severity, deadline)
		if err != nil {
			t.Errorf("waitForAlert(%s): %v", expected.RuleID, err)
			res.Reason = err.Error()
			res.Passed = false
			return res
		}
		if !ok {
			t.Errorf("expected rule %s did not fire on host %s within %s",
				expected.RuleID, hostID, deadline)
			res.Reason = "rule did not fire within SLA: " + expected.RuleID
			res.Passed = false
			return res
		}
	}
	return res
}

// runNoise drives one noise scenario and returns whether the host stayed
// alert-free across the entire `within_seconds` window declared in
// noise/expected.yaml. The window is used (rather than a fixed short
// settle) because a slow-firing rule that produces an FP at second 25
// would otherwise sneak past a 2-second settle and inflate efficacy.
func runNoise(t *testing.T, stack *integration.Stack, entry scenarioEntry) result {
	t.Helper()
	res := result{Name: entry.Name, Kind: "noise"}

	hostID := entry.Scenario.Host.ID
	ctx := t.Context()
	token, err := enroll(ctx, stack, hostID, entry.Name)
	if err != nil {
		t.Errorf("enroll: %v", err)
		res.Reason = err.Error()
		return res
	}

	if err := entry.Scenario.PostDirect(ctx, stack.Server.URL, token); err != nil {
		t.Errorf("PostDirect: %v", err)
		res.Reason = err.Error()
		return res
	}

	// Honor the scenario's declared no-alert window. expected.yaml's
	// within_seconds is the budget for "if a rule WERE going to fire, it
	// would have by now"; settling for less defeats the gate. Fall back
	// to the short noiseSettle ceiling if a noise scenario forgot to
	// declare within_seconds (still useful for orchestration smoke).
	wait := noiseSettle
	if entry.Expected.WithinSeconds > 0 {
		wait = time.Duration(entry.Expected.WithinSeconds) * time.Second
	}
	select {
	case <-time.After(wait):
	case <-ctx.Done():
		res.Reason = ctx.Err().Error()
		return res
	}

	alerts, err := stack.DetectionService().ListAlerts(ctx, detectionapi.AlertFilter{HostID: hostID, Limit: 50})
	if err != nil {
		t.Errorf("ListAlerts: %v", err)
		res.Reason = err.Error()
		return res
	}
	if len(alerts) == 0 {
		res.Passed = true
		return res
	}
	// At least one alert fired, which is a false positive. Surface the
	// rule_id list so the operator knows which rule got greedy.
	ruleIDs := make([]string, 0, len(alerts))
	for _, a := range alerts {
		ruleIDs = append(ruleIDs, a.RuleID)
	}
	t.Errorf("noise scenario %s produced %d unexpected alerts: %s",
		entry.Name, len(alerts), strings.Join(ruleIDs, ", "))
	res.Reason = fmt.Sprintf("unexpected alerts: %s", strings.Join(ruleIDs, ", "))
	return res
}

// waitForAlert polls the detection service's ListAlerts for an alert with
// the given rule_id + severity on the given host. Returns true on first
// match within the deadline.
func waitForAlert(ctx context.Context, stack *integration.Stack, hostID, ruleID, severity string, deadline time.Duration) (bool, error) {
	stop := time.Now().Add(deadline)
	for time.Now().Before(stop) {
		alerts, err := stack.DetectionService().ListAlerts(ctx, detectionapi.AlertFilter{HostID: hostID, Limit: 50})
		if err != nil {
			return false, err
		}
		for _, a := range alerts {
			if a.RuleID == ruleID && (severity == "" || a.Severity == severity) {
				return true, nil
			}
		}
		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return false, nil
}

// enroll posts to /api/enroll with integration.EnrollSecret and returns the
// issued host token on success. Returns (token, "") on success; on any
// failure returns ("", err) so the caller can record a per-scenario
// failure result and let the parent test append it to the aggregate.
//
// Note this deliberately does NOT use require.NoError / require.Equal:
// those call t.FailNow internally, which aborts the subtest goroutine
// BEFORE the parent's appendResultM runs, leaving the scenario missing
// from the aggregate denominator. A missing scenario inflates the
// detection rate by reducing the denominator, so the harness would silently
// claim "100% detection" even when half the scenarios failed to enrol.
func enroll(ctx context.Context, stack *integration.Stack, hostID, scenarioName string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"enroll_secret": integration.EnrollSecret,
		"hardware_uuid": hostID,
		"hostname":      "l6-efficacy-" + scenarioName + ".local",
		"agent_version": "l6-efficacy-test",
		"os_version":    "macOS 26.0",
	})
	if err != nil {
		return "", fmt.Errorf("marshal enroll body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		stack.Server.URL+"/api/enroll", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build enroll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := stack.Server.Client().Do(req)
	if err != nil {
		return "", fmt.Errorf("POST /api/enroll: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST /api/enroll for %s: HTTP %d", hostID, resp.StatusCode)
	}

	var er struct {
		HostID    string `json:"host_id"`
		HostToken string `json:"host_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return "", fmt.Errorf("decode enroll response: %w", err)
	}
	if er.HostID != hostID {
		return "", fmt.Errorf("enroll response host_id=%q != requested %q", er.HostID, hostID)
	}
	if er.HostToken == "" {
		return "", fmt.Errorf("enroll response missing host_token")
	}
	return er.HostToken, nil
}
