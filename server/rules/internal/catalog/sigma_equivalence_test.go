package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"go.yaml.in/yaml/v3"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// The equivalence gate for issue #761.
//
// Each of these rules decides on the POSITION of a token in argv, which Sigma cannot express, so the positional facts are computed
// as fields instead (server/rules/internal/sigmabind/argv.go). Before any Go matcher is deleted, the replacement has to be shown
// equivalent, and over a far larger input space than the 5 + 14 + 9 table cases these rules carry today.
//
// So these are property tests: generate an argv from a vocabulary rich enough to reach the interesting shapes, run the Go matcher
// and the field-based predicate the Sigma rule will use, and require the same verdict. A vocabulary matters here; uniformly random
// strings would essentially never produce a match, and the test would pass while exercising nothing.

// The generated argv is drawn by CATEGORY first and then by token, rather than uniformly from one flat list. That matters more than
// it looks: the empty string is the single token the two implementations disagree about, and in a flat 23-token vocabulary the
// three-token shape that exposes the disagreement turns up about once in 28,000 draws, so a 100-case run passes while never
// reaching it. Drawing a category first gives the empty string its own sixth of the probability mass, and the property below
// actually fails without the documented exception.
var argvCategories = map[string][]string{
	"flag":       {"-v", "-q", "-w", "-S", "-p"},
	"subcommand": {"dump-keychain", "help", "list-keychains", "load", "bootstrap", "print", "unload"},
	// Case variants, so a detection that folds case where the Go matcher does not is caught rather than assumed absent.
	"casevariant": {"DUMP-KEYCHAIN", "Dump-Keychain", "LOAD", "Bootstrap", "dyld_insert_libraries=/tmp/x", "Dyld_Library_Path=/tmp"},
	"plist":       {"/Library/LaunchAgents/evil.plist", "/Users/victor/Library/LaunchAgents/x.plist", "/tmp/a.plist"},
	"assignment":  {"DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "DYLD_LIBRARY_PATH=/tmp", "A=1", "PATH=/bin"},
	"empty":       {""},
	"other":       {"prog", "/usr/bin/true", "gui/501", "/etc/passwd"},
}

var argvCategoryNames = []string{"flag", "subcommand", "plist", "assignment", "empty", "other", "casevariant"}

// drawArgv models a command INVOCATION rather than emitting token soup, and that distinction decides whether this test is worth
// anything.
//
// A first attempt drew each position independently from a flat vocabulary. It passed, and it was worthless: the shape that exposes
// the one real divergence between the two launch-agent implementations needs an empty token in one specific position, a verb in the
// next and a matching plist after that, which independent draws reach about once in 2,600 cases. Against a 100-case run the property
// passed while never once exercising its own exception, and a mutation that removed the exception entirely still passed.
//
// Modelling the invocation gives each discriminating choice its own draw, so the divergence turns up in roughly a tenth of cases.
// The mutation now fails, which is the only evidence that the property is testing anything. A quarter of draws stay free-form so
// shapes not modelled here still occur.
func drawArgv(t *rapid.T) []string {
	if rapid.IntRange(0, 3).Draw(t, "freeform") == 0 {
		n := rapid.IntRange(0, 6).Draw(t, "argc")
		argv := make([]string, 0, n)
		for i := range n {
			category := rapid.SampledFrom(argvCategoryNames).Draw(t, "cat"+string(rune('0'+i)))
			argv = append(argv, rapid.SampledFrom(argvCategories[category]).Draw(t, "tok"+string(rune('0'+i))))
		}
		return argv
	}

	argv := []string{rapid.SampledFrom([]string{"launchctl", "security", "env", "sh"}).Draw(t, "argv0")}
	for range rapid.IntRange(0, 2).Draw(t, "leadingFlags") {
		argv = append(argv, rapid.SampledFrom(argvCategories["flag"]).Draw(t, "leadingFlag"))
	}
	// The token the two implementations read differently. Drawn as its own coin flip so it is reached constantly rather than by
	// coincidence.
	if rapid.Bool().Draw(t, "emptyBeforeSubcommand") {
		argv = append(argv, "")
	}
	argv = append(argv, rapid.SampledFrom([]string{"load", "bootstrap", "dump-keychain", "help"}).Draw(t, "verb"))
	for range rapid.IntRange(1, 3).Draw(t, "operands") {
		category := rapid.SampledFrom([]string{"plist", "plist", "assignment", "other", "flag", "empty", "casevariant"}).Draw(t, "operandCat")
		argv = append(argv, rapid.SampledFrom(argvCategories[category]).Draw(t, "operand"))
	}
	return argv
}

// skipsAnEmptyBeforeItsSubcommand reports the one shape the two launch-agent implementations are known to read differently: an empty
// token sitting between argv[0] and the first real operand.
//
// extractLaunchctlSubcommand skips it, because it uses "" as its not-found sentinel and cannot record an empty verb; the computed
// field treats it AS the verb, which is what launchctl itself would do, and then declines to fire. The difference is a deliberate
// correction rather than a regression: `launchctl "" load x.plist` loads nothing, so firing on it is a false positive. It is also in
// the safe direction, and the shape does not occur in real telemetry (of 59 empty-argument execs on a dev host, every one was
// `sudo -p ""`, and none was launchctl).
func skipsAnEmptyBeforeItsSubcommand(argv []string) bool {
	for i, a := range argv {
		if i == 0 || strings.HasPrefix(a, "-") {
			continue
		}
		return a == ""
	}
	return false
}

// evalCompiled evaluates an already-compiled detection against an exec event. Used for a rule that has been converted, so the
// property tests the detection the pack actually ships rather than a copy of it in this file.
func evalCompiled(t require.TestingT, rule *sigma.Rule, path string, argv []string) bool {
	payload, err := json.Marshal(map[string]any{"pid": 1, "ppid": 0, "path": path, "args": argv})
	require.NoError(t, err)
	ev, err := sigmabind.NewEvent(rulesapi.Event{EventID: "e", EventType: "exec", Payload: payload})
	require.NoError(t, err)
	return rule.Matches(ev)
}

// evalDetection compiles a real Sigma detection block and evaluates it against an exec event, so these properties test the rule PR B
// will actually ship rather than a Go stand-in for it.
//
// This matters more than it sounds. The first version of this test substituted a Go map lookup for the detection, and a map lookup
// is case-sensitive while an ordinary Sigma value is not. `security DUMP-KEYCHAIN` would have been reported equivalent even though
// the real rule fires on it and the Go matcher does not. Compiling the detection is the only way the property can see that, which is
// why the generator below also draws case variants.
func evalDetection(t require.TestingT, detection, path string, argv []string) bool {
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(detection), &doc))
	rule, err := sigma.Compile(doc)
	require.NoError(t, err)

	payload, err := json.Marshal(map[string]any{"pid": 1, "ppid": 0, "path": path, "args": argv})
	require.NoError(t, err)
	ev, err := sigmabind.NewEvent(rulesapi.Event{EventID: "e", EventType: "exec", Payload: payload})
	require.NoError(t, err)
	require.NoError(t, sigmabind.Validate(rule, "exec"), "every field the detection reads must be one we supply")
	return rule.Matches(ev)
}

// The detections below are the ones PR B will author into the pack files. Each uses |re where the Go matcher is case-SENSITIVE:
// a plain Sigma value folds case, and `security DUMP-KEYCHAIN` or `DYLD_INSERT_LIBRARIES=` in another case would then fire where
// the Go rule does not. |re is applied verbatim by this evaluator, which is what makes it the faithful choice here.
const (
	launchAgentDetection = `
selection:
  Subcommand|re: '^(load|bootstrap)$'
  CommandArguments|re: '(?i)(^|/)(Users/[^/]+/)?Library/LaunchAgents/[^/]+\.plist$'
condition: selection
`
	dyldDetection = `
selection:
  EnvAssignments|re: '^DYLD_(INSERT_LIBRARIES|LIBRARY_PATH)='
condition: selection
`
)

// legacyFindDumpKeychainArg is credential_keychain_dump's Go matcher as it stood before the conversion, kept verbatim as the
// oracle for the property below.
//
// Retaining it is deliberate. The gate #761 asks for is that the converted rule detect exactly what the Go one did, and that claim
// is only checkable while both exist. Frozen here, it becomes the specification of the pre-conversion behaviour: any later drift in
// the detection block fails against it, so a change to what this rule detects has to be made deliberately and in both places rather
// than noticed later from an absence of alerts.
func legacyFindDumpKeychainArg(argv []string) (string, bool) {
	for i, a := range argv {
		if i == 0 {
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if legacyDumpKeychainTokens[a] {
			return a, true
		}
		return "", false
	}
	return "", false
}

// legacyDumpKeychainTokens and legacySecurityBinaryPaths are the two value sets the Go rule matched against, frozen alongside it.
// The live values now live in the pack file's detection block, and TestShippedDetectionMatchesTheFrozenTokens holds them together.
var legacyDumpKeychainTokens = map[string]bool{"dump-keychain": true}

var legacySecurityBinaryPaths = map[string]bool{"/usr/bin/security": true}

// legacyKeychainFires is the COMPLETE pre-conversion predicate: the rule required the exact binary AND the flagged subcommand.
// Comparing only the argv half would leave the binary check outside the gate, so widening selection_binary would pass unnoticed.
func legacyKeychainFires(path string, argv []string) bool {
	if !legacySecurityBinaryPaths[path] {
		return false
	}
	_, ok := legacyFindDumpKeychainArg(argv)
	return ok
}

// TestEquivalence_KeychainDump: the Go matcher and the shipped detection agree on every generated invocation.
func TestEquivalence_KeychainDump(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		argv := drawArgv(t)
		// Paths drawn from the frozen set, near-misses, and case variants: the binary half of the conjunction is as much a part
		// of the rule as the subcommand, and holding it constant would leave any widening of selection_binary untested.
		path := rapid.SampledFrom([]string{
			"/usr/bin/security", "/usr/local/bin/security", "/usr/bin/SECURITY", "/tmp/security",
			"/usr/bin/securityd", "/bin/sh",
		}).Draw(t, "path")

		goFires := legacyKeychainFires(path, argv)
		sigmaFires := evalCompiled(t, keychainDetection(), path, argv)
		require.Equal(t, goFires, sigmaFires, "path=%q argv=%q", path, argv)
	})
}

// TestEquivalence_LaunchAgent: as above, with one documented exception.
//
// The exception is asserted rather than excused: where the two differ, the input MUST be the known empty-token shape, and the
// difference MUST be Go firing where the detection does not. That keeps the carve-out from hiding any other divergence, and pins
// that the correction only ever removes findings.
func TestEquivalence_LaunchAgent(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		argv := drawArgv(t)
		sub, plist := extractLaunchctlSubcommand(argv)
		goFires := (sub == "load" || sub == "bootstrap") && plist != "" && launchAgentPath.MatchString(plist)
		sigmaFires := evalDetection(t, launchAgentDetection, "/bin/launchctl", argv)

		if goFires != sigmaFires {
			require.True(t, skipsAnEmptyBeforeItsSubcommand(argv),
				"undocumented divergence: argv=%q go=%v sigma=%v", argv, goFires, sigmaFires)
			require.True(t, goFires && !sigmaFires,
				"the correction must only ever remove findings, never add them: argv=%q", argv)
			return
		}
		require.Equal(t, goFires, sigmaFires, "argv=%q", argv)
	})
}

// TestEquivalence_DyldInsert: as above, across both env-style and ordinary binaries.
func TestEquivalence_DyldInsert(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		path := rapid.SampledFrom([]string{"/usr/bin/env", "/opt/homebrew/bin/env", "/bin/sh", "/usr/bin/true"}).Draw(t, "path")
		argv := drawArgv(t)
		goFires := matchDyldArg(path, argv) != ""
		sigmaFires := evalDetection(t, dyldDetection, path, argv)
		require.Equal(t, goFires, sigmaFires, "path=%q argv=%q", path, argv)
	})
}

// TestLaunchAgentEmptySubcommandIsTheOneDeliberateChange pins the exception as an example, so the behaviour change is visible in a
// named test rather than living only inside a property's escape hatch.
func TestLaunchAgentEmptySubcommandIsTheOneDeliberateChange(t *testing.T) {
	t.Parallel()

	argv := []string{"launchctl", "", "load", "/Library/LaunchAgents/evil.plist"}

	sub, plist := extractLaunchctlSubcommand(argv)
	require.Equal(t, "load", sub, "the Go matcher skips the empty token and reaches load")
	require.NotEmpty(t, plist)

	require.False(t, evalDetection(t, launchAgentDetection, "/bin/launchctl", argv),
		"the computed field treats the empty token as the verb, which is what launchctl would do, so the rule declines")
}

// TestDetectionsAreCaseSensitiveWhereGoIs pins the reason each detection uses |re. A plain Sigma value folds case, so
// `Subcommand: dump-keychain` would fire on `security DUMP-KEYCHAIN` while the Go matcher, a map lookup, does not.
func TestDetectionsAreCaseSensitiveWhereGoIs(t *testing.T) {
	t.Parallel()

	_, goFires := legacyFindDumpKeychainArg([]string{"security", "DUMP-KEYCHAIN"})
	require.False(t, goFires, "the Go matcher was a case-sensitive map lookup")
	require.False(t, evalCompiled(t, keychainDetection(), "/usr/bin/security", []string{"security", "DUMP-KEYCHAIN"}),
		"the shipped detection must not fold case either")

	require.True(t, evalCompiled(t, keychainDetection(), "/usr/bin/security", []string{"security", "dump-keychain"}),
		"and it must still fire on the real spelling")

	// The same trap on the binary half. The property covers this only when a case-variant path and a real subcommand happen to be
	// drawn together, which is likely but not certain; a known trap deserves a deterministic test rather than a probable one.
	require.False(t, legacyKeychainFires("/usr/bin/SECURITY", []string{"security", "dump-keychain"}),
		"the Go rule matched the binary against an exact set")
	require.False(t, evalCompiled(t, keychainDetection(), "/usr/bin/SECURITY", []string{"security", "dump-keychain"}),
		"so the shipped detection must not fold case on Image either")

	// The same trap on the other side: Sigma's |startswith folds case, so it would match a lowercased assignment key that
	// strings.HasPrefix in the Go matcher rejects.
	require.Empty(t, matchDyldArg("/usr/bin/true", []string{"dyld_insert_libraries=/tmp/x"}))
	require.False(t, evalDetection(t, dyldDetection, "/usr/bin/true", []string{"dyld_insert_libraries=/tmp/x"}))
	require.NotEmpty(t, matchDyldArg("/usr/bin/true", []string{"DYLD_INSERT_LIBRARIES=/tmp/x"}))
	require.True(t, evalDetection(t, dyldDetection, "/usr/bin/true", []string{"DYLD_INSERT_LIBRARIES=/tmp/x"}))
}

// TestShippedDetectionMatchesTheFrozenTokens ties the frozen oracle to the shipped file. The subcommand set moved out of Go and into
// the detection block, so nothing would otherwise notice if the two drifted apart and the property started comparing the rule
// against a set it no longer uses.
func TestShippedDetectionMatchesTheFrozenTokens(t *testing.T) {
	t.Parallel()

	for path := range legacySecurityBinaryPaths {
		for token := range legacyDumpKeychainTokens {
			require.True(t, evalCompiled(t, keychainDetection(), path, []string{"security", token}),
				"the shipped detection must still match %q + %q, which the frozen oracle expects", path, token)
		}
	}
	require.False(t, evalCompiled(t, keychainDetection(), "/usr/bin/security", []string{"security", "list-keychains"}),
		"and must not have quietly widened by subcommand")
	require.False(t, evalCompiled(t, keychainDetection(), "/usr/local/bin/security", []string{"security", "dump-keychain"}),
		"nor by binary path")
}
