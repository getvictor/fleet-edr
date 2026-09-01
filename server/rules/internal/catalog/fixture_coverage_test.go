package catalog

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/rules/api"
)

// Regression fixtures for the whole catalog (issue #773).
//
// At twelve hand-written rules a reviewer could hold the catalog in their head. At seventy-eight they cannot, and a rule that
// quietly stops matching looks exactly like a rule nothing tripped. The fixtures are what turn that silence into a failure: each
// one is a committed event sequence with the finding it must produce, replayed through the real decode / graph / evaluate path.
//
// Two tests, deliberately separate, because they fail for different reasons and a reader should be able to tell which happened:
//
//   - TestEveryCatalogRuleHasARegressionFixture is the COVERAGE gate. It answers "does every rule have one".
//   - TestCatalogFixturesStillFire is the REGRESSION gate. It answers "does every fixture still produce what it claims".
//
// Folding them together would report a brand-new rule with no fixture and a shipped rule that broke as the same failure.

// fixtureResolver is the exclusion resolver every rule is built with here.
//
// One resolver for the whole catalog rather than a bespoke one per rule, because these fixtures are replayed by a loop over
// New() and a rule cannot be handed its own construction from inside that loop. The entries below are therefore a published part
// of the fixture contract: a fixture that wants to prove the exclusion path suppresses a finding uses one of these values, and
// its rule's own doc names it.
func fixtureResolver() api.ExclusionResolver {
	return &fakeExclusions{entries: []fakeExcl{
		// sudoers_tamper/negative_writer_allowlisted.json writes to sudoers from this path and must stay silent.
		{ruleID: "sudoers_tamper", matchType: api.ExclusionMatchPathGlob, value: "/usr/local/bin/fixture-allowed-writer"},
		// privilege_launchd_plist_write/negative_allowlisted_team_id.json is signed by this synthetic team.
		{ruleID: "privilege_launchd_plist_write", matchType: api.ExclusionMatchTeamID, value: "FIXTURE-ALLOW"},
	}}
}

// pendingFixtures lists the rules that do NOT yet have a fixture, asserted as an exact set.
//
// An exact set rather than a skip: a skipped subtest is invisible in a passing run, and a list that is merely "allowed to be
// missing" grows quietly. Asserting equality means a NEW rule without a fixture fails (it is not on the list), and a rule that
// GAINS one also fails until it is struck off, so the list can only shrink.
//
// DO NOT ADD TO THIS LIST. It is the imported SigmaHQ corpus, which gets its smoke fixtures in the follow-up to #773; every entry
// is scheduled for deletion, and a new rule belongs in fixtures/, not here.
var pendingFixtures = []string{
	"proc_creation_macos_applescript",
	"proc_creation_macos_binary_padding",
	"proc_creation_macos_change_file_time_attr",
	"proc_creation_macos_chflags_hidden_flag",
	"proc_creation_macos_clear_system_logs",
	"proc_creation_macos_clipboard_access_via_osascript",
	"proc_creation_macos_create_account",
	"proc_creation_macos_create_hidden_account",
	"proc_creation_macos_creds_from_keychain",
	"proc_creation_macos_csrutil_disable",
	"proc_creation_macos_csrutil_status",
	"proc_creation_macos_disable_security_tools",
	"proc_creation_macos_dscl_add_user_to_admin_group",
	"proc_creation_macos_dseditgroup_add_to_admin_group",
	"proc_creation_macos_dsenableroot_enable_root_account",
	"proc_creation_macos_file_and_directory_discovery",
	"proc_creation_macos_find_cred_in_files",
	"proc_creation_macos_gui_input_capture",
	"proc_creation_macos_hdiutil_create",
	"proc_creation_macos_hdiutil_mount",
	"proc_creation_macos_installer_susp_child_process",
	"proc_creation_macos_ioreg_discovery",
	"proc_creation_macos_jamf_susp_child",
	"proc_creation_macos_jamf_usage",
	"proc_creation_macos_jxa_in_memory_execution",
	"proc_creation_macos_launchctl_execution",
	"proc_creation_macos_local_account",
	"proc_creation_macos_local_groups",
	"proc_creation_macos_network_service_scanning",
	"proc_creation_macos_network_sniffing",
	"proc_creation_macos_nscurl_usage",
	"proc_creation_macos_office_susp_child_processes",
	"proc_creation_macos_osacompile_runonly_execution",
	"proc_creation_macos_payload_decoded_and_decrypted",
	"proc_creation_macos_persistence_via_plistbuddy",
	"proc_creation_macos_remote_access_tools_meshagent_arguments",
	"proc_creation_macos_remote_access_tools_teamviewer_incoming_connection",
	"proc_creation_macos_remote_system_discovery",
	"proc_creation_macos_schedule_task_job_cron",
	"proc_creation_macos_screencapture",
	"proc_creation_macos_security_software_discovery",
	"proc_creation_macos_space_after_filename",
	"proc_creation_macos_split_file_into_pieces",
	"proc_creation_macos_susp_browser_child_process",
	"proc_creation_macos_susp_execution_macos_script_editor",
	"proc_creation_macos_susp_find_execution",
	"proc_creation_macos_susp_histfile_operations",
	"proc_creation_macos_susp_in_memory_download_and_compile",
	"proc_creation_macos_susp_macos_firmware_activity",
	"proc_creation_macos_susp_system_network_discovery",
	"proc_creation_macos_suspicious_applet_behaviour",
	"proc_creation_macos_swvers_discovery",
	"proc_creation_macos_sysadminctl_add_user_to_admin_group",
	"proc_creation_macos_sysadminctl_enable_guest_account",
	"proc_creation_macos_sysctl_discovery",
	"proc_creation_macos_system_network_connections_discovery",
	"proc_creation_macos_system_profiler_discovery",
	"proc_creation_macos_system_shutdown_reboot",
	"proc_creation_macos_tail_base64_decode_from_image",
	"proc_creation_macos_tmutil_delete_backup",
	"proc_creation_macos_tmutil_disable_backup",
	"proc_creation_macos_tmutil_exclude_file_from_backup",
	"proc_creation_macos_wizardupdate_malware_infection",
	"proc_creation_macos_xattr_gatekeeper_bypass",
	"proc_creation_macos_xcsset_malware_infection",
}

// TestEveryCatalogRuleHasARegressionFixture is the coverage half: every rule the server registers carries at least one fixture
// that says it fires, or is on the shrinking pending list.
func TestEveryCatalogRuleHasARegressionFixture(t *testing.T) {
	t.Parallel()

	var missing []string
	for _, r := range New(fixtureResolver()) {
		if !hasPositiveFixture(t, r.ID()) {
			missing = append(missing, r.ID())
		}
	}
	slices.Sort(missing)

	want := slices.Clone(pendingFixtures)
	slices.Sort(want)
	assert.Equal(t, want, missing,
		"rules without a positive regression fixture changed. A rule ADDED here needs fixtures/<rule_id>/positive_*.json; a rule "+
			"REMOVED from the pending list needs striking off it. Do not grow the list.")
}

// spec:server-detection-rules-engine/a-converted-rule-carries-its-logic-in-its-file/a-converted-rule-detects-what-it-detected-before
// spec:server-detection-rules-engine/dns-correlated-c2-beacon-detection/a-suspicious-process-resolves-a-domain-and-connects-to-the-resolved-address
// spec:server-detection-rules-engine/dns-correlated-c2-beacon-detection/a-browser-resolving-and-connecting-to-an-ordinary-domain-does-not-fire
// spec:server-detection-rules-engine/dns-correlated-c2-beacon-detection/a-suspicious-process-that-connects-to-an-address-it-never-resolved-does-not-fire
//
// TestCatalogFixturesStillFire is the regression half: every fixture that exists still produces exactly the findings it records.
//
// Driven off the catalog rather than off the fixture directories, so a fixture directory named after a rule that no longer exists
// is caught as a stale directory rather than silently skipped.
//
// The scenario markers above moved here from the per-rule replay tests this loop replaced, ALL of them: leaving any behind would
// attach a fixture scenario to whichever test happened to follow it, which for the DNS rule was its ATT&CK mapping test. Each
// still holds, and the first holds wider, since the converted-rule scenario is now asserted for every converted rule rather than
// for one. The three beacon scenarios are carried by the positive and two negative fixtures under fixtures/dns_c2_beacon/, which
// this loop replays. Replay lives in exactly one place so a rule cannot be built two different ways against the same fixtures.
func TestCatalogFixturesStillFire(t *testing.T) {
	t.Parallel()

	for _, r := range New(fixtureResolver()) {
		dir := filepath.Join("fixtures", r.ID())
		if _, err := os.Stat(dir); err != nil {
			continue // covered by the coverage gate above; not this test's failure to report.
		}
		t.Run(r.ID(), func(t *testing.T) {
			t.Parallel()
			detectiontestkit.Replay(t, r, dir)
		})
	}
}

// TestNoOrphanFixtureDirectories catches the reverse of the coverage gate: a fixture directory whose rule is gone.
//
// Without this a renamed or deleted rule leaves its fixtures behind, and they stop being replayed by anything while still looking
// like coverage to a reader browsing the tree.
func TestNoOrphanFixtureDirectories(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("fixtures")
	require.NoError(t, err, "read fixtures dir")

	known := map[string]bool{}
	for _, r := range New(nil) {
		known[r.ID()] = true
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		assert.True(t, known[e.Name()],
			"fixtures/%s names no rule in the catalog: delete it, or rename it to the rule it belongs to", e.Name())
	}
}

// hasPositiveFixture reports whether the rule has at least one fixture asserting it FIRES.
//
// A directory of only negative cases is not coverage: it proves the rule stays quiet, which a rule that has stopped working
// entirely also does. The positive case is the one that fails when a rule silently dies, which is the whole point of #773.
func hasPositiveFixture(t *testing.T, ruleID string) bool {
	t.Helper()

	// Walked recursively rather than globbed at the top level, because Replay walks recursively: its own doc offers
	// `<dir>/sudoers/positive_overwrite.json` as a supported layout. A top-level glob would report a rule whose positive lives in
	// a subdirectory as uncovered while the replay gate happily ran it, so the two gates would disagree and the only way to
	// satisfy both would be to duplicate the fixture at the top level. Discovery has to match the thing it is gating.
	var paths []string
	err := filepath.WalkDir(filepath.Join("fixtures", ruleID), func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".json") {
			paths = append(paths, path)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return false // no directory at all: uncovered, which is the coverage gate's business to report.
	}
	require.NoError(t, err)
	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // fixture path built from a catalog rule id, not user input
		require.NoErrorf(t, err, "read %s", path)
		var c detectiontestkit.FixtureCase
		require.NoErrorf(t, json.Unmarshal(raw, &c), "decode %s", path)
		if len(c.ExpectedFindings) > 0 {
			// The naming convention is not load-bearing (the assertion above is), but a positive case named negative_* is a
			// mistake worth catching at the point where someone is most likely to make it.
			assert.Falsef(t, strings.HasPrefix(filepath.Base(path), "negative_"),
				"%s expects findings but is named negative_*", path)
			return true
		}
	}
	return false
}
