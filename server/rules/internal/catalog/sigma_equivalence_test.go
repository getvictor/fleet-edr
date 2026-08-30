package catalog

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
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
	"plist":      {"/Library/LaunchAgents/evil.plist", "/Users/victor/Library/LaunchAgents/x.plist", "/tmp/a.plist"},
	"assignment": {"DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "DYLD_LIBRARY_PATH=/tmp", "A=1", "PATH=/bin"},
	"empty":      {""},
	"other":      {"prog", "/usr/bin/true", "gui/501", "/etc/passwd"},
}

var argvCategoryNames = []string{"flag", "subcommand", "plist", "assignment", "empty", "other"}

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
		category := rapid.SampledFrom([]string{"plist", "plist", "assignment", "other", "flag", "empty"}).Draw(t, "operandCat")
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

// fieldsOf runs an exec event through the real adapter and returns the computed fields a Sigma rule would see.
func fieldsOf(t require.TestingT, path string, argv []string) func(string) []string {
	payload, err := json.Marshal(map[string]any{"pid": 1, "ppid": 0, "path": path, "args": argv})
	require.NoError(t, err)
	ev, err := sigmabind.NewEvent(rulesapi.Event{EventID: "e", EventType: "exec", Payload: payload})
	require.NoError(t, err)
	return func(name string) []string {
		v, _ := ev.Field(name)
		return v
	}
}

// TestEquivalence_KeychainDump: the Go matcher fires exactly when the computed Subcommand is a flagged one.
func TestEquivalence_KeychainDump(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		argv := drawArgv(t)
		_, goFires := findDumpKeychainArg(argv)

		field := fieldsOf(t, "/usr/bin/security", argv)
		sigmaFires := slices.ContainsFunc(field("Subcommand"), func(s string) bool { return dumpKeychainArgTokens()[s] })

		require.Equal(t, goFires, sigmaFires, "argv=%q subcommand=%q", argv, field("Subcommand"))
	})
}

// TestEquivalence_LaunchAgent: the Go matcher fires exactly when the computed Subcommand is load or bootstrap AND one of the
// computed CommandArguments is a LaunchAgent plist path, with one documented exception.
//
// The exception is asserted rather than excused: where the two differ, the input MUST be the known empty-token shape, and the
// difference MUST be Go firing where the field-based rule does not. That keeps the carve-out from hiding any other divergence, and
// pins that the correction only ever removes findings.
func TestEquivalence_LaunchAgent(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		argv := drawArgv(t)
		sub, plist := extractLaunchctlSubcommand(argv)
		goFires := (sub == "load" || sub == "bootstrap") && plist != "" && launchAgentPath.MatchString(plist)

		field := fieldsOf(t, "/bin/launchctl", argv)
		sigmaFires := slices.ContainsFunc(field("Subcommand"), func(s string) bool { return s == "load" || s == "bootstrap" }) &&
			slices.ContainsFunc(field("CommandArguments"), launchAgentPath.MatchString)

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

// TestLaunchAgentEmptySubcommandIsTheOneDeliberateChange pins the exception as an example, so the behaviour change is visible in a
// named test rather than living only inside a property's escape hatch.
func TestLaunchAgentEmptySubcommandIsTheOneDeliberateChange(t *testing.T) {
	t.Parallel()

	argv := []string{"launchctl", "", "load", "/Library/LaunchAgents/evil.plist"}

	sub, plist := extractLaunchctlSubcommand(argv)
	require.Equal(t, "load", sub, "the Go matcher skips the empty token and reaches load")
	require.NotEmpty(t, plist)

	field := fieldsOf(t, "/bin/launchctl", argv)
	require.Empty(t, field("Subcommand"),
		"the computed field treats the empty token as the verb, which is what launchctl would do, so the rule declines")
}

// TestEquivalence_DyldInsert: the Go matcher fires exactly when one of the computed EnvAssignments carries a DYLD prefix.
func TestEquivalence_DyldInsert(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		path := rapid.SampledFrom([]string{"/usr/bin/env", "/opt/homebrew/bin/env", "/bin/sh", "/usr/bin/true"}).Draw(t, "path")
		argv := drawArgv(t)
		goFires := matchDyldArg(path, argv) != ""

		field := fieldsOf(t, path, argv)
		sigmaFires := slices.ContainsFunc(field("EnvAssignments"), func(a string) bool {
			for _, prefix := range dyldPrefixes {
				if len(a) >= len(prefix) && a[:len(prefix)] == prefix {
					return true
				}
			}
			return false
		})

		require.Equal(t, goFires, sigmaFires, "path=%q argv=%q env=%q", path, argv, field("EnvAssignments"))
	})
}
