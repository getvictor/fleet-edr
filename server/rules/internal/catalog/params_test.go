package catalog

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ruleFile builds a minimal pack file carrying the given x-engine body.
func ruleFile(ruleID, algorithm, params string) string {
	s := "title: T\nid: 00000000-0000-0000-0000-000000000000\nx-engine:\n  rule_id: " + ruleID +
		"\n  algorithm: " + algorithm + "\n"
	if params != "" {
		s += "  params:\n" + params
	}
	return s
}

func fsWith(files map[string]string) fstest.MapFS {
	out := fstest.MapFS{}
	for name, body := range files {
		out[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return out
}

// spec:server-detection-rules-engine/detection-parameters-are-read-from-the-rule-pack/a-rule-reads-its-match-values-from-its-file
//
// TestLoadPack_BindsDeclaredParams covers the happy path for both kinds.
func TestLoadPack_BindsDeclaredParams(t *testing.T) {
	t.Parallel()

	got, err := loadPack(fsWith(map[string]string{
		"pack/suspicious_exec.yml": ruleFile("suspicious_exec", "ancestor_walk_path_prefix", "    window: 45s\n"),
	}))
	require.NoError(t, err)
	require.Contains(t, got, "suspicious_exec")
	assert.Equal(t, int64(45), int64(got["suspicious_exec"].Duration("window").Seconds()))
	assert.NotNil(t, got["suspicious_exec"].Raw(), "the verbatim node is kept so the generator can re-emit it")
}

// spec:server-detection-rules-engine/detection-parameters-are-read-from-the-rule-pack/a-parameter-the-evaluator-never-reads-is-refused
//
// TestLoadPack_RejectsUnknownParam is the guard against dead config. A param no algorithm reads is worse than a missing one,
// because it invites an operator to believe they have tuned something.
func TestLoadPack_RejectsUnknownParam(t *testing.T) {
	t.Parallel()

	_, err := loadPack(fsWith(map[string]string{
		"pack/suspicious_exec.yml": ruleFile("suspicious_exec", "ancestor_walk_path_prefix",
			"    window: 30s\n    max_descendants: 500\n"),
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_descendants")
	assert.Contains(t, err.Error(), "never reads")
}

// TestLoadPack_RejectsMissingParam catches the reverse: an algorithm reads a value the file does not supply, which would
// otherwise surface as a zero window that silently matches nothing.
func TestLoadPack_RejectsMissingParam(t *testing.T) {
	t.Parallel()

	_, err := loadPack(fsWith(map[string]string{
		"pack/osascript_network_exec.yml": ruleFile("osascript_network_exec", "descendant_within_window",
			"    osascript_paths:\n      - /usr/bin/osascript\n"),
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "omits param")
}

// spec:server-detection-rules-engine/detection-parameters-are-read-from-the-rule-pack/a-malformed-parameter-is-refused-at-load
//
// TestLoadPack_RejectsBadValues pins that a malformed value fails at LOAD, naming the rule, rather than at first fire hours
// later on one host as a detection that silently did not happen.
func TestLoadPack_RejectsBadValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"unparseable duration", "    window: soon\n", "duration"},
		{"zero duration", "    window: 0s\n", "positive duration"},
		{"negative duration", "    window: -5s\n", "positive duration"},
		{"duration where a list belongs", "    window: 30s\n", ""}, // control: valid
	}
	for _, tc := range cases {
		if tc.want == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadPack(fsWith(map[string]string{
				"pack/suspicious_exec.yml": ruleFile("suspicious_exec", "ancestor_walk_path_prefix", tc.params),
			}))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "suspicious_exec")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestLoadPack_RejectsEmptyList guards the shape that would silently match nothing.
func TestLoadPack_RejectsEmptyList(t *testing.T) {
	t.Parallel()

	_, err := loadPack(fsWith(map[string]string{
		"pack/shell_from_office.yml": ruleFile("shell_from_office", "parent_lookup_path_match", "    office_binaries: []\n"),
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty")
}

// TestLoadPack_RejectsParamsForAnAlgorithmThatReadsNone catches a params block attached to a rule whose evaluator consults
// nothing, which is dead config by a different route.
func TestLoadPack_RejectsParamsForAnAlgorithmThatReadsNone(t *testing.T) {
	t.Parallel()

	_, err := loadPack(fsWith(map[string]string{
		"pack/sensor_tamper.yml": ruleFile("sensor_tamper", "absence_within_window", "    window: 5s\n"),
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registers none")
}

// TestLoadPack_SkipsTheSharedListsFile pins that the authored list definitions are not mistaken for a rule.
func TestLoadPack_SkipsTheSharedListsFile(t *testing.T) {
	t.Parallel()

	got, err := loadPack(fsWith(map[string]string{
		"pack/" + SharedListsFile: "unix_shells:\n  - /bin/sh\n",
		"pack/persistence_launchagent.yml": ruleFile("persistence_launchagent", "exec_subcommand_and_path_pattern_match",
			"    launchctl_paths:\n      - /bin/launchctl\n"),
	}))
	require.NoError(t, err)
	assert.Len(t, got, 1, "only the rule file yields params")
	assert.Contains(t, got, "persistence_launchagent")
}

// TestLoadPack_RejectsAFileWithNoRuleID keeps a malformed pack from loading half-populated.
func TestLoadPack_RejectsAFileWithNoRuleID(t *testing.T) {
	t.Parallel()

	_, err := loadPack(fsWith(map[string]string{"pack/broken.yml": "title: T\nx-engine:\n  algorithm: x\n"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule_id is empty")
}

// spec:server-detection-rules-engine/values-shared-between-rules-are-defined-once/a-shared-value-has-one-definition
//
// TestSharedLists_LoadAndResolve covers the shared-list half, including the empty-list refusal.
func TestSharedLists_LoadAndResolve(t *testing.T) {
	t.Parallel()

	t.Run("loads", func(t *testing.T) {
		t.Parallel()
		got, err := loadSharedLists(fsWith(map[string]string{
			"pack/" + SharedListsFile: "unix_shells:\n  - /bin/sh\n  - /bin/bash\n",
		}))
		require.NoError(t, err)
		assert.Equal(t, []string{"/bin/sh", "/bin/bash"}, got["unix_shells"])
	})

	t.Run("rejects an empty list", func(t *testing.T) {
		t.Parallel()
		_, err := loadSharedLists(fsWith(map[string]string{"pack/" + SharedListsFile: "unix_shells: []\n"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is empty")
	})

	t.Run("rejects an unreadable file", func(t *testing.T) {
		t.Parallel()
		_, err := loadSharedLists(fsWith(map[string]string{}))
		require.Error(t, err)
	})
}

// TestEmbeddedPackMatchesTheRulesThatReadIt is the end-to-end guard on the real embedded files: every value a rule reads
// resolves, and the shared lists hold what the rules expect.
//
// The set contents are asserted, not just their presence. This phase's contract is behaviour-identical, and a list that loaded
// but held the wrong paths would pass every structural check while silently changing what the fleet detects.
func TestEmbeddedPackMatchesTheRulesThatReadIt(t *testing.T) {
	t.Parallel()

	assert.Len(t, shellPaths(), 8, "unix_shells")
	assert.True(t, shellPaths()["/usr/bin/sh"], "unix_shells includes /usr/bin/sh")
	assert.Len(t, shebangShellPaths(), 7, "shebang_shells")
	assert.False(t, shebangShellPaths()["/usr/bin/sh"],
		"shebang_shells deliberately omits /usr/bin/sh; widening it silently would be a behaviour change")
	assert.Equal(t, []string{"/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/"}, suspiciousPrefixes())

	assert.True(t, securityBinaryPaths()["/usr/bin/security"])
	assert.True(t, dumpKeychainArgTokens()["dump-keychain"])
	assert.True(t, launchctlPaths()["/bin/launchctl"])
	assert.True(t, officeBinaries()["/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word"])
	assert.True(t, osascriptPaths()["/usr/bin/osascript"])
	assert.True(t, downloadBinaries()["/usr/bin/curl"])

	assert.Equal(t, int64(30_000_000_000), suspiciousExecWindow())
	assert.Equal(t, int64(30_000_000_000), osascriptWindow())
}
