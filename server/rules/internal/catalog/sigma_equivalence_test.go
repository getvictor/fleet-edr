package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

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

// env's own options, one per group that the parser treats differently: accepted and valueless, accepted with a separate operand,
// accepted with an attached operand, the end-of-options marker, the lone-dash synonym, an option env does not have, and the two
// that make the outer argument vector stop describing what env applied. Drawn for the env shape in drawArgv so the carve-out
// below covers each group rather than whichever one happened to be sampled.
var envOptionTokens = []string{"-i", "-v", "-u", "PATH", "-uPATH", "--", "-", "-q", "-0", "-S"}

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

	// An env invocation whose assignments sit BEHIND its option prefix, drawn as its own shape for the same reason the empty
	// token below is: it is the input the two dyld implementations now disagree about, and the structured branch cannot otherwise
	// produce it, because it always puts a verb between the flags and the operands and both implementations stop at the verb.
	// Without this the divergence turns up only through the free-form branch, at a rate low enough that the property passed while
	// never exercising its own carve-out, and a mutation removing the carve-out survived.
	if rapid.Bool().Draw(t, "envAssignmentsBehindOptions") {
		// A refusal shape roughly a third of the time, so the removed-finding carve-out is reached rather than only asserted.
		// An empty-name assignment is drawn here rather than added to the assignment category, which other shapes reuse.
		refusal := rapid.IntRange(0, 2).Draw(t, "envRefusal") == 0
		if refusal {
			argv = append(argv, rapid.SampledFrom([]string{"=bad", "=", "=DYLD_INSERT_LIBRARIES"}).Draw(t, "emptyName"))
		}
		// With a refusal drawn, the option run may be EMPTY, and it has to be able to be: the legacy oracle stops at the first
		// token without an equals sign, so an option between the empty name and the assignments makes both sides report nothing
		// and the divergence never appears. Mutation testing caught exactly that, with the carve-out surviving every seed.
		lo := 1
		if refusal {
			lo = 0
		}
		for range rapid.IntRange(lo, 2).Draw(t, "envOptions") {
			argv = append(argv, rapid.SampledFrom(envOptionTokens).Draw(t, "envOption"))
		}
		for range rapid.IntRange(1, 2).Draw(t, "envAssignments") {
			argv = append(argv, rapid.SampledFrom(argvCategories["assignment"]).Draw(t, "envAssignment"))
		}
		argv = append(argv, rapid.SampledFrom([]string{"prog", "/usr/bin/true"}).Draw(t, "envCommand"))
		return argv
	}

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
// legacyExtractLaunchctlSubcommand skips it, because the matcher it copies
// used "" as its not-found sentinel and cannot record an empty verb; the computed
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

// Every property below evaluates the detection block the pack actually SHIPS, via evalCompiled. There is deliberately no helper
// left that compiles a detection from a string in this file: while one existed, a property could pass against a copy of a rule
// rather than the rule, which is the shape that let a case-folding divergence hide in #790.

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

// legacyExtractLaunchctlSubcommand and legacyMatchDyldArg are the launch-agent and DYLD matchers as they stood before conversion,
// frozen here for the same reason as the keychain one: the gate #761 asks for is only checkable while both implementations exist.
//
// legacyLaunchctlPaths is the binary set the launch-agent rule required. Freezing it matters as much as the argv half. In #793 the
// property compared only the argv half of the keychain rule and left the binary check outside the gate, so a widening of
// selection_binary would have passed unnoticed; review caught it. These properties compare the complete conjunction from the start.
var legacyLaunchctlPaths = map[string]bool{"/bin/launchctl": true, "/usr/bin/launchctl": true}

// Frozen COPIES of the values the pre-conversion rules matched against, deliberately not the live launchAgentPath and
// dyldPrefixes that production still uses.
//
// This is the difference between an oracle and a mirror. Review caught that the first version of these helpers read the live
// symbols: a change to either would have moved both sides of the property together, and it would have kept passing while the
// rule's meaning changed. Frozen literals mean the property compares the shipped detection against what the rule detected on the
// day it was converted, which is the only comparison worth making. TestLiveSymbolsStillAgreeWithTheShippedDetections ties the live
// values back to the detection separately, so the two are kept in step without either one being able to hide a drift.
var legacyLaunchAgentPath = regexp.MustCompile(`(?i)(^|/)(Users/[^/]+/)?Library/LaunchAgents/[^/]+\.plist$`)

var legacyDyldPrefixes = []string{"DYLD_INSERT_LIBRARIES=", "DYLD_LIBRARY_PATH="}

func legacyExtractLaunchctlSubcommand(args []string) (subcommand, plistPath string) {
	for i := 1; i < len(args); i++ {
		if args[i] == "" || strings.HasPrefix(args[i], "-") {
			continue
		}
		if subcommand == "" {
			subcommand = args[i]
			continue
		}
		if legacyLaunchAgentPath.MatchString(args[i]) {
			return subcommand, args[i]
		}
	}
	return subcommand, ""
}

// legacyLaunchAgentFires is the COMPLETE pre-conversion predicate: the exact binary, a registering subcommand, and a LaunchAgent
// plist among the later arguments.
func legacyLaunchAgentFires(path string, argv []string) bool {
	if !legacyLaunchctlPaths[path] {
		return false
	}
	sub, plist := legacyExtractLaunchctlSubcommand(argv)
	if sub != "load" && sub != "bootstrap" {
		return false
	}
	return plist != "" && legacyLaunchAgentPath.MatchString(plist)
}

// legacyMatchDyldArg is the reference the property compares the shipped detection against.
//
// Corrected for issue #792, which changed what this rule detects rather than how it is written. The previous version stopped the
// assignment scan at the first token without "=", so an option ahead of the assignment ended it and the injection was invisible;
// it also scanned from args[0], which for env is env's own name and never an assignment it performs.
//
// Written from the stated rule rather than by calling the production helper, so the property still catches a transcription error
// between the Sigma definition and the intent. What it no longer proves is that the two were derived independently, since the same
// person wrote both; the named tests below carry the cases that matter on their own.
func legacyMatchDyldArg(path string, args []string) string {
	matched := func(a string) string {
		for _, prefix := range legacyDyldPrefixes {
			if strings.HasPrefix(a, prefix) {
				return prefix + "<redacted>"
			}
		}
		return ""
	}

	if path != "/usr/bin/env" && !strings.HasSuffix(path, "/env") {
		// Shell form: the assignment is the first argument or it is not an assignment at all.
		if len(args) == 0 {
			return ""
		}
		return matched(args[0])
	}

	// env form: args[0] is env's own name, then the run of assignments env performs.
	//
	// This oracle deliberately does NOT model env's option grammar, and an earlier round of this PR was wrong to give it a copy.
	// Two reasons, and the second is the one that matters.
	//
	// The grammar is intricate (attached operands, clusters, options env does not have, two options after which the outer
	// argument vector stops describing anything), it was corrected twice under review, and a second copy has to be corrected in
	// lockstep or the property compares one bug against another. Review caught the copy disagreeing with production on `-uS`
	// and on `-z`.
	//
	// More importantly, mirroring production here would make the property agree BY CONSTRUCTION on the very behaviour #792
	// changed, which is the one thing an independent oracle must not do. What the legacy Go matcher actually did was stop at the
	// first token that was not an assignment, and env's own options stopped it too: that WAS the bug. Preserving it keeps the
	// property measuring the fix, and the divergence is asserted as the documented exception in TestEquivalence_DyldInsert
	// rather than hidden. One source for env's option grammar, and it is production's.
	for i := 1; i < len(args); i++ {
		if !strings.Contains(args[i], "=") {
			break
		}
		if m := matched(args[i]); m != "" {
			return m
		}
	}
	return ""
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
		path := rapid.SampledFrom([]string{
			"/bin/launchctl", "/usr/bin/launchctl", "/usr/local/bin/launchctl", "/bin/LAUNCHCTL", "/tmp/launchctl", "/bin/sh",
		}).Draw(t, "path")

		goFires := legacyLaunchAgentFires(path, argv)
		sigmaFires := evalCompiled(t, launchAgentDetection(), path, argv)

		if goFires != sigmaFires {
			require.True(t, skipsAnEmptyBeforeItsSubcommand(argv),
				"undocumented divergence: path=%q argv=%q go=%v sigma=%v", path, argv, goFires, sigmaFires)
			require.True(t, goFires && !sigmaFires,
				"the correction must only ever remove findings, never add them: path=%q argv=%q", path, argv)
			return
		}
		require.Equal(t, goFires, sigmaFires, "path=%q argv=%q", path, argv)
	})
}

// TestEquivalence_DyldInsert: as above, across both env-style and ordinary binaries, with THREE documented exceptions.
//
// The exception runs the OPPOSITE way to the launch-agent one, which is why it is stated separately rather than folded into the
// same helper. That conversion only ever removes findings; this one deliberately ADDS them. #792 fixed a bug in the Go matcher,
// which stopped its scan at env's first option and so reported nothing for `env -i DYLD_INSERT_LIBRARIES=x prog`, an injection it
// was written to catch. The frozen oracle in this file still reproduces that bug on purpose, since its job is to say what the Go
// matcher did rather than what it should have done.
//
// So each divergence is asserted rather than excused, by shape and by direction. The detection fires where the matcher did not
// for an env invocation whose assignments sit behind an option prefix; the matcher fires where the detection does not for an
// invocation env would refuse, and for a non-env invocation whose argv[0] is an assignment, which is the shape issue #791
// removed. Anything else is a real regression. Anything else is a
// real regression. In particular this pins that no divergence appears for a non-env path, for an env invocation with no option
// prefix, or in the narrowing direction.
func TestEquivalence_DyldInsert(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		path := rapid.SampledFrom([]string{"/usr/bin/env", "/opt/homebrew/bin/env", "/bin/sh", "/usr/bin/true"}).Draw(t, "path")
		argv := drawArgv(t)
		goFires := legacyMatchDyldArg(path, argv) != ""
		sigmaFires := evalCompiled(t, dyldDetection(), path, argv)

		if goFires != sigmaFires {
			// Two deliberate divergences, in OPPOSITE directions, each asserted with its own shape so neither can excuse the
			// other. Review found the second one missing, which would have failed this property the first time the generator
			// drew a refusal shape.
			switch {
			case sigmaFires && !goFires:
				require.True(t, hidesAnAssignmentBehindAnEnvOption(path, argv),
					"undocumented ADDED finding: path=%q argv=%q", path, argv)
			case goFires && !sigmaFires:
				require.True(t, envWouldRefuseTheInvocation(path, argv) || readsOnlyTheShellForm(path, argv),
					"undocumented REMOVED finding: path=%q argv=%q", path, argv)
			}
			return
		}
		require.Equal(t, goFires, sigmaFires, "path=%q argv=%q", path, argv)
	})
}

// readsOnlyTheShellForm reports the second shape whose finding this conversion REMOVES: a non-env invocation whose argv[0] is an
// assignment, which the legacy Go matcher read and the narrowed rule does not.
//
// Issue #791 measured that shape as unreachable in production, at zero across 670,185 exec events, because ESF serialises the
// argument vector and never the environment a shell applies. The property generator produces it freely, which is exactly why the
// divergence has to be stated here rather than discovered as a flake.
func readsOnlyTheShellForm(path string, argv []string) bool {
	if path == "/usr/bin/env" || strings.HasSuffix(path, "/env") {
		return false
	}
	return len(argv) > 0 && strings.Contains(argv[0], "=")
}

// envWouldRefuseTheInvocation reports the shapes for which env exits before executing anything, so the corrected parser reports
// nothing where the legacy Go matcher happily reported an assignment. Those are findings the fix REMOVES, which is the opposite
// direction to the carve-out below and needs its own statement.
//
// Shape-based on purpose, for the same reason as its sibling: naming the token forms rather than re-deciding them keeps this from
// agreeing with production by construction. It is deliberately BROADER than production, since its job is to say "a refusal was
// plausible here", not to decide the refusal.
func envWouldRefuseTheInvocation(path string, argv []string) bool {
	if path != "/usr/bin/env" && !strings.HasSuffix(path, "/env") {
		return false
	}
	for _, a := range argv[min(1, len(argv)):] {
		switch {
		case strings.HasPrefix(a, "="):
			// An assignment with an empty name: env calls setenv, gets EINVAL, and exits.
			return true
		case a == "--":
			return false
		case len(a) > 1 && a[0] == '-':
			// An option env does not have, or one after which the outer argv describes nothing. Left broad rather than
			// enumerated here so the oracle does not become a second option parser.
			return true
		case strings.Contains(a, "="):
			continue
		default:
			// The command. Nothing after it is env's to refuse.
			return false
		}
	}
	return false
}

// hidesAnAssignmentBehindAnEnvOption reports the one shape the two dyld implementations are known to read differently: an env
// invocation in which an option-looking token sits between argv[0] and the first assignment, which is where the Go matcher stopped
// scanning and the corrected parser does not.
//
// Deliberately a statement about the SHAPE of the input rather than a second copy of the option parser. Re-implementing the parse
// here would make the carve-out agree with production by construction, which is the one thing an independent oracle must not do.
func hidesAnAssignmentBehindAnEnvOption(path string, argv []string) bool {
	if path != "/usr/bin/env" && !strings.HasSuffix(path, "/env") {
		return false
	}
	sawOption := false
	for _, a := range argv[min(1, len(argv)):] {
		if strings.Contains(a, "=") {
			// Reached an assignment. It diverges only if an option came first, which is what stopped the Go matcher.
			return sawOption
		}
		if strings.HasPrefix(a, "-") {
			sawOption = true
		}
	}
	return false
}

// spec:server-detection-rules-engine/converting-a-rule-may-narrow-what-it-detects-never-widen-it/a-conversion-removes-a-finding-rather-than-adding-one
//
// TestLaunchAgentEmptySubcommandIsTheOneDeliberateChange pins the exception as an example, so the behaviour change is visible in a
// named test rather than living only inside a property's escape hatch.
func TestLaunchAgentEmptySubcommandIsTheOneDeliberateChange(t *testing.T) {
	t.Parallel()

	argv := []string{"launchctl", "", "load", "/Library/LaunchAgents/evil.plist"}

	sub, plist := legacyExtractLaunchctlSubcommand(argv)
	require.Equal(t, "load", sub, "the Go matcher skipped the empty token and reached load")
	require.NotEmpty(t, plist)

	require.False(t, evalCompiled(t, launchAgentDetection(), "/bin/launchctl", argv),
		"the computed field treats the empty token as the verb, which is what launchctl would do, so the rule declines")
}

// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/an-option-before-an-assignment-does-not-hide-it
//
// TestEnvOptionPrefixIsTheOtherDeliberateChange pins the dyld divergence as an example, so the behaviour change is visible in a
// named test rather than living only inside a property's escape hatch. Same reason as the launch-agent one above, and the same
// shape of evidence, but the opposite direction: this conversion ADDS a finding the Go matcher missed.
//
// It also covers a gap mutation testing exposed in the property. Disabling the generator's env shape leaves the property passing
// vacuously, because nothing else it draws reaches the divergence, and no assertion inside the property can notice that. This test
// can: it names the input.
func TestEnvOptionPrefixIsTheOtherDeliberateChange(t *testing.T) {
	t.Parallel()

	// The injection #792 reported nothing for. env applies the assignment and execs prog, so this is a real dylib injection.
	argv := []string{"env", "-i", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "prog"}

	require.Empty(t, legacyMatchDyldArg("/usr/bin/env", argv),
		"the Go matcher stopped at env's own option and reported nothing, which was the bug")
	require.True(t, evalCompiled(t, dyldDetection(), "/usr/bin/env", argv),
		"the shipped detection must see past the option prefix and fire")

	// And the correction is bounded: an option env does not have still reports nothing, because env execs nothing at all.
	refused := []string{"env", "-z", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "prog"}
	require.False(t, evalCompiled(t, dyldDetection(), "/usr/bin/env", refused),
		"an invocation env would refuse must not produce a finding for an injection that never happened")
}

// spec:server-detection-rules-engine/argument-position-is-available-as-a-field/an-assignment-with-an-empty-name-reports-nothing-at-all
//
// TestEnvRefusalRemovesAFindingDeterministically is the removed-finding direction of the same divergence, pinned by name for the
// same reason as its sibling: mutation testing showed the property reaches this only because the generator draws the shape, and no
// assertion inside the property can notice if that draw stops happening.
func TestEnvRefusalRemovesAFindingDeterministically(t *testing.T) {
	t.Parallel()

	// env exits `setenv =bad: Invalid argument` and execs nothing, so the assignment behind it was never applied.
	argv := []string{"env", "=bad", "DYLD_INSERT_LIBRARIES=/tmp/e.dylib", "prog"}

	require.NotEmpty(t, legacyMatchDyldArg("/usr/bin/env", argv),
		"the Go matcher walked past the empty name and reported the assignment, which is the fabrication being removed")
	require.False(t, evalCompiled(t, dyldDetection(), "/usr/bin/env", argv),
		"the shipped detection must report nothing for an invocation env refuses to run")
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
	// The env form, since #791 narrowed the rule to it. The case-folding trap this pins is unchanged by that narrowing.
	lower := []string{"env", "dyld_insert_libraries=/tmp/x", "prog"}
	upper := []string{"env", "DYLD_INSERT_LIBRARIES=/tmp/x", "prog"}
	require.Empty(t, legacyMatchDyldArg("/usr/bin/env", lower))
	require.False(t, evalCompiled(t, dyldDetection(), "/usr/bin/env", lower))
	require.NotEmpty(t, legacyMatchDyldArg("/usr/bin/env", upper))
	require.True(t, evalCompiled(t, dyldDetection(), "/usr/bin/env", upper))

	// The binary half of the launch-agent rule, the same trap #793's review found in the keychain one.
	require.False(t, legacyLaunchAgentFires("/bin/LAUNCHCTL", []string{"launchctl", "load", "/Library/LaunchAgents/x.plist"}))
	require.False(t, evalCompiled(t, launchAgentDetection(), "/bin/LAUNCHCTL",
		[]string{"launchctl", "load", "/Library/LaunchAgents/x.plist"}),
		"the shipped detection must not fold case on Image either")
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

// TestLiveSymbolsStillAgreeWithTheShippedDetections keeps the values production still reads in step with the detection blocks that
// now decide the rules.
//
// Two symbols survived their rules' conversion because a finding has to NAME what fired and the evaluator reports only that some
// element matched: launchAgentPath re-finds which argument was the plist, and dyldPrefixes re-finds which assignment was the DYLD
// one. Both therefore restate a criterion the detection block already owns, and review was right that this is a drift path. Until
// the evaluator can report the matched element (issue #796), these assertions are what stops the two descriptions of one criterion
// from parting company: a detection widened without the Go symbol would produce findings with an empty variable or path.
func TestLiveSymbolsStillAgreeWithTheShippedDetections(t *testing.T) {
	t.Parallel()

	t.Run("every dyldPrefixes entry is one the shipped detection matches", func(t *testing.T) {
		t.Parallel()
		for _, prefix := range dyldPrefixes {
			// The env form, since #791 narrowed the rule to it: the shell form this used to pass never reaches the server.
			require.True(t, evalCompiled(t, dyldDetection(), "/usr/bin/env", []string{"env", prefix + "/tmp/x", "prog"}),
				"the detection must fire on %q, or a finding built from it would name nothing", prefix)
		}
	})

	t.Run("the detection matches nothing dyldPrefixes cannot name", func(t *testing.T) {
		t.Parallel()
		// A variable the detection accepts but the slice does not would produce a finding with an empty variable name.
		for _, candidate := range []string{"DYLD_FRAMEWORK_PATH=", "DYLD_FALLBACK_LIBRARY_PATH=", "DYLD_PRINT_LIBRARIES="} {
			if !evalCompiled(t, dyldDetection(), "/usr/bin/env", []string{"env", candidate + "/tmp/x", "prog"}) {
				continue
			}
			require.Contains(t, dyldPrefixes, candidate,
				"the detection fires on %q but dyldPrefixes cannot name it, so the finding would be blank", candidate)
		}
	})

	t.Run("launchAgentPath agrees with the detection's target criterion", func(t *testing.T) {
		t.Parallel()
		paths := []string{
			"/Library/LaunchAgents/x.plist", "/Users/victor/Library/LaunchAgents/x.plist",
			"/tmp/x.plist", "/Library/LaunchDaemons/x.plist", "/Library/LaunchAgents/x.txt",
		}
		for _, path := range paths {
			viaDetection := evalCompiled(t, launchAgentDetection(), "/bin/launchctl", []string{"launchctl", "load", path})
			require.Equalf(t, launchAgentPath.MatchString(path), viaDetection,
				"the Go regexp and the detection must agree on %q, or the alert would name a path the rule did not fire on", path)
		}
	})
}

// The shell_from_office oracle. Frozen literals, not the live shared list or params, for the reason the others are: an oracle that
// reads what production reads moves with it and proves nothing.
var (
	legacyShellPaths = map[string]bool{
		"/bin/sh": true, "/bin/bash": true, "/bin/zsh": true, "/bin/dash": true,
		"/usr/bin/sh": true, "/usr/bin/bash": true, "/usr/bin/zsh": true, "/usr/bin/dash": true,
	}
	legacyOfficeBinaries = map[string]bool{
		"/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word":             true,
		"/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel":           true,
		"/Applications/Microsoft PowerPoint.app/Contents/MacOS/Microsoft PowerPoint": true,
		"/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook":       true,
	}
)

// legacyShellFromOfficeFires is the complete pre-conversion predicate: an exact shell path whose parent is an exact Office binary.
func legacyShellFromOfficeFires(path, parentPath string) bool {
	return legacyShellPaths[path] && legacyOfficeBinaries[parentPath]
}

// TestEquivalence_ShellFromOffice compares the shipped detection against the frozen oracle over both halves of the predicate: the
// shell being executed and the parent that spawned it. ParentImage is supplied to the adapter the way the rule supplies it.
func TestEquivalence_ShellFromOffice(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/bin/sh", "/bin/bash", "/usr/bin/zsh", "/bin/DASH", "/tmp/bash", "/usr/local/bin/sh", "/bin/ls", "",
	}
	parents := []string{
		"/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
		"/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel",
		"/Applications/Microsoft WORD.app/Contents/MacOS/Microsoft Word",
		"/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
		"/tmp/Microsoft Word", "/bin/zsh", "",
	}

	rapid.Check(t, func(t *rapid.T) {
		path := rapid.SampledFrom(paths).Draw(t, "path")
		parent := rapid.SampledFrom(parents).Draw(t, "parent")

		payload, err := json.Marshal(map[string]any{"pid": 1, "ppid": 2, "path": path, "args": []string{path}})
		require.NoError(t, err)
		ev, err := sigmabind.NewExecEvent(rulesapi.Event{EventID: "e", EventType: "exec", Payload: payload}, parent)
		require.NoError(t, err)

		require.Equal(t, legacyShellFromOfficeFires(path, parent), shellFromOfficeDetection().Matches(ev),
			"path=%q parent=%q", path, parent)
	})
}

// TestSharedShellListMatchesTheShippedDetection is the guard the detection block's comment promises.
//
// Sigma cannot reference a list defined elsewhere, so converting a rule that read the shared `unix_shells` list necessarily inlined
// it. suspicious_exec still reads the shared list, so the two descriptions of one set can part company.
//
// Compares the SETS rather than sampling either side, which review caught: checking that each shared entry fires, plus a handful of
// hand-picked non-shells, still passed when a path was added to the detection alone. The detection's alternatives are read out of
// the shipped pack file, so both directions of drift fail here.
func TestSharedShellListMatchesTheShippedDetection(t *testing.T) {
	t.Parallel()

	body, err := os.ReadFile("pack/shell_from_office.yml")
	require.NoError(t, err)
	m := regexp.MustCompile(`Image\|re: '\^\(([^)]*)\)\$'`).FindSubmatch(body)
	require.NotNil(t, m, "the detection must declare its shells as an anchored alternation")

	inDetection := map[string]bool{}
	for alt := range strings.SplitSeq(string(m[1]), "|") {
		inDetection[strings.ReplaceAll(alt, `\.`, ".")] = true
	}

	shared := map[string]bool{}
	for path := range shellPaths() {
		shared[path] = true
	}

	assert.Equal(t, shared, inDetection,
		"the inlined detection and the shared unix_shells list must describe the same set; they are one set written twice")
}

// The sudoers_tamper oracle. Frozen literals, not the live regexp or masks.
var (
	legacySudoersPath      = regexp.MustCompile(`^(?:/private)?/etc/sudoers(?:\.d/[^/]+)?$`)
	legacySudoersWriteMask = 0x3
	legacySudoersIntent    = 0x400 | 0x8 | 0x200
)

// legacySudoersFires is the complete pre-conversion predicate, including the suppression that a single write-intent boolean could
// not express: the intent mask applies ONLY when the writer is sudo.
func legacySudoersFires(path string, flags int, subjectPath string) bool {
	if !legacySudoersPath.MatchString(path) {
		return false
	}
	if flags&legacySudoersWriteMask == 0 {
		return false
	}
	if subjectPath == "/usr/bin/sudo" && flags&legacySudoersIntent == 0 {
		return false
	}
	return true
}

// isLockWithoutSudo is the one input shape on which the shipped rule and the frozen oracle now disagree: a writer OTHER than sudo
// opening a sudoers file write-mode with no content-changing bits.
//
// The oracle fires on it, because its suppression was scoped to sudo alone. The adapter now withholds TargetFilename for every
// such open, so the rule cannot see it: #801 moved the lock-versus-modification decision out of the rule and into the field
// supplier, which is what lets the rule be plain Sigma. Sudo's own flock is suppressed by both, and every content-changing open
// fires in both, so this shape is the whole of the difference.
//
// Named and shared with the equivalence carve-out rather than written twice, so the carve-out cannot drift into excusing a
// divergence the oracle never had.
func isLockWithoutSudo(flags int, subjectPath string) bool {
	return subjectPath != "/usr/bin/sudo" && flags&legacySudoersWriteMask != 0 && flags&legacySudoersIntent == 0
}

// TestEquivalence_SudoersTamper compares the shipped detection against the frozen oracle across paths, flag combinations and
// writers, with ONE documented exception (#801).
//
// The exception is a lock taken by someone other than sudo: write access with no content-changing bits. The oracle fires on it,
// because its suppression named sudo alone; the adapter now withholds TargetFilename for every such open, so the rule cannot see
// it. Asserted rather than excused, the way the launch-agent and dyld carve-outs are: where the two differ the input MUST be that
// shape, and the difference MUST be the detection declining where Go fired. Any other divergence, in either direction, fails.
//
// The flag space is chosen deliberately: read-only, write-without-intent (a lock), and write-with-intent are the three cases the
// flags distinguish, and keeping all three is what makes the carve-out narrow rather than a licence.
//
// Exhaustive rather than sampled. The domain is 8 paths x 7 flag sets x 4 writers = 224 cases, which is smaller than rapid's
// default 100 draws would reliably cover, so sampling could leave a regression isolated to one tuple passing.
func TestEquivalence_SudoersTamper(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/etc/sudoers", "/private/etc/sudoers", "/etc/sudoers.d/evil", "/private/etc/sudoers.d/edr-uat",
		"/etc/sudoers.d/", "/etc/sudoersX", "/etc/passwd", "/etc/sudoers.d/a/b",
	}
	flagSets := []int{
		0x0,                 // O_RDONLY
		0x1,                 // O_WRONLY, no mutating bits: sudo's flock shape
		0x2,                 // O_RDWR, no mutating bits
		0x1 | 0x400,         // O_WRONLY|O_TRUNC
		0x1 | 0x200 | 0x400, // what the extension actually emits
		0x8,                 // O_APPEND alone, no write access
		0x2 | 0x8,           // O_RDWR|O_APPEND
	}
	subjects := []string{"/usr/bin/sudo", "/usr/bin/tee", "/bin/cp", ""}

	checked := 0
	for _, path := range paths {
		for _, flags := range flagSets {
			for _, subject := range subjects {
				writer := subject
				if writer == "" {
					writer = "an unresolved writer"
				}
				checked++
				t.Run(fmt.Sprintf("%s flags=%#x by %s", path, flags, writer), func(t *testing.T) {
					t.Parallel()
					payload, err := json.Marshal(map[string]any{"pid": 7, "path": path, "flags": flags})
					require.NoError(t, err)
					ev, err := sigmabind.NewOpenEventLazy(
						rulesapi.Event{EventID: "e", EventType: "open", Payload: payload},
						func() (string, error) { return subject, nil })
					require.NoError(t, err)

					goFires := legacySudoersFires(path, flags, subject)
					sigmaFires := sudoersDetection().Matches(ev)
					if goFires != sigmaFires {
						require.True(t, isLockWithoutSudo(flags, subject),
							"undocumented divergence: path=%q flags=%#x writer=%q go=%v sigma=%v", path, flags, writer, goFires, sigmaFires)
						require.True(t, goFires && !sigmaFires,
							"moving the decision to the adapter can only REMOVE this finding, never add one: path=%q flags=%#x", path, flags)
						return
					}
					require.Equal(t, goFires, sigmaFires)
				})
			}
		}
	}
	assert.Equal(t, len(paths)*len(flagSets)*len(subjects), checked, "every combination must be exercised")
}

// TestSudoersOpenFlagsAreSyntheticWhichIsWhyTheFieldsWereRetired records the measurement #801 turned on, so a later reader finds
// the reasoning rather than wondering why a file rule reads no flags.
//
// Since #301 (2026-05-31) the only source of `open` events is FileTamperSubscriber, which re-emits ESF NOTIFY_CREATE and
// NOTIFY_WRITE on /etc/sudoers* with a CONSTANT synthetic flag set, `O_WRONLY|O_CREAT|O_TRUNC`. Against that constant both flag
// tests the rule used to carry were no-ops: write access is always set, and the mutating bits are always set, so the sudo
// suppression could never fire.
//
// They could not be made real either, which is what settled the question. Real open(2) flags need broad NOTIFY_OPEN, and
// ADR-0008 drops it: ESF silently ignores per-event-type muting for OPEN, so it cannot be scoped, and the ADR's own words for
// subscribing to it anyway are that it "is not how top EDRs collect file telemetry".
func TestSudoersOpenFlagsAreSyntheticWhichIsWhyTheFieldsWereRetired(t *testing.T) {
	t.Parallel()

	const synthetic = 0x1 | 0x200 | 0x400 // what FileTamperSubscriber emits, verified against captured telemetry as flags=1537
	require.Equal(t, 1537, synthetic)

	assert.NotZero(t, synthetic&legacySudoersWriteMask, "write access is always set, so that test always passed")
	assert.NotZero(t, synthetic&legacySudoersIntent, "the mutating bits are always set, so the sudo suppression could never fire")

	// What the retirement did NOT do, which is the part worth pinning. sudo's flock is still not an alert: the decision moved
	// from a rule condition into the adapter, so the rule never sees the event rather than seeing it and excusing it. The
	// fixture behind this measured 30 alerts in 15 minutes on one host when the suppression was absent, so this is not
	// theoretical.
	flock := boundOpenEvent(t, "/etc/sudoers", 0x1, "/usr/bin/sudo")
	_, present := flock.Field("TargetFilename")
	assert.False(t, present, "a lock is not a modification, so the adapter does not report one")
	assert.False(t, sudoersDetection().Matches(flock))

	// And what it DID cost: the same shape by another writer is now invisible too, where the rule's suppression named sudo alone.
	assert.True(t, legacySudoersFires("/etc/sudoers", 0x1, "/usr/bin/tee"), "the oracle fired on it")
	assert.False(t, sudoersDetection().Matches(boundOpenEvent(t, "/etc/sudoers", 0x1, "/usr/bin/tee")))
}

// TestReadOnlyOpensAreFilteredByTheAdapterNotTheRule pins where the guarantee moved.
//
// The rule used to carry `WriteIntent: true` so it would reject a read-only open "on its own terms", for an engine that supplies
// TargetFilename on every open. Retiring that field does not make read-only opens alert here, because sigmabind supplies
// TargetFilename ONLY for an event carrying write access, and that gate is now the single place write access is consulted. An
// agent predating #301 still sends real flags, so this is the check that keeps a read of /etc/sudoers quiet on such a host.
//
// Asserted through the adapter rather than through a literal field map, because the adapter IS the guarantee now.
func TestReadOnlyOpensAreFilteredByTheAdapterNotTheRule(t *testing.T) {
	t.Parallel()

	readOnly := boundOpenEvent(t, "/etc/sudoers", 0x0, "/bin/cat")
	_, present := readOnly.Field("TargetFilename")
	assert.False(t, present, "a read-only open must not be reported as a file modification")
	assert.False(t, sudoersDetection().Matches(readOnly))

	writing := boundOpenEvent(t, "/etc/sudoers", 0x1|0x200|0x400, "/bin/cp")
	assert.True(t, sudoersDetection().Matches(writing))
}

// boundOpenEvent builds the ADAPTER's view of an open event, which is what every sudoers assertion here evaluates
// against. Distinct from sigmabatch_test.go's openEventFor, which builds the raw api.Event a batch carries.
func boundOpenEvent(t *testing.T, path string, flags int, subject string) *sigmabind.Event {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"pid": 7, "path": path, "flags": flags})
	require.NoError(t, err)
	ev, err := sigmabind.NewOpenEventLazy(
		rulesapi.Event{EventID: "e", EventType: "open", Payload: payload},
		func() (string, error) { return subject, nil })
	require.NoError(t, err)
	return ev
}

// spec:server-detection-rules-engine/a-rule-suppresses-a-named-exception/the-suppression-applies-only-to-what-it-names
//
// TestANamedSuppressionAppliesOnlyToWhatItNames pins the engine capability the requirement describes: a rule states an exception
// as a named set of field tests its condition subtracts, and the exception applies only to events matching EVERY test in it.
//
// Tested against a literal detection rather than a shipped rule, and that is the honest subject: the requirement is about what
// the engine lets a rule express, not about any one rule using it. It used to be tested through sudoers_tamper's flock
// suppression, which #801 retired because the field it read was inert; the capability itself did not change, and the corpus still
// depends on it, which the count below asserts rather than assumes.
func TestANamedSuppressionAppliesOnlyToWhatItNames(t *testing.T) {
	t.Parallel()

	rule, err := sigma.Compile(map[string]any{
		"selection": map[string]any{"Image|endswith": "/arp"},
		"filter_known_caller": map[string]any{
			"ParentImage|endswith": "/wifivelocityd",
		},
		"condition": "selection and not filter_known_caller",
	})
	require.NoError(t, err)

	cases := []struct {
		name   string
		parent string
		want   bool
	}{
		{"the named caller is suppressed", "/usr/libexec/wifivelocityd", false},
		{"a different caller performing the same exec fires", "/bin/zsh", true},
		{"a lookalike elsewhere on disk fires", "/tmp/wifivelocityd-not-really", true},
		{"an unresolved caller is not suppressed", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := fieldsEvent{"Image": {"/usr/sbin/arp"}, "ParentImage": {tc.parent}}
			assert.Equal(t, tc.want, rule.Matches(ev))
		})
	}
}

// TestTheImportedCorpusDependsOnSubtractedFilters is why the capability above is not speculative. The shipped pack stopped using
// it when #801 retired the sudoers suppression, so without this the requirement would rest on a test rule alone.
func TestTheImportedCorpusDependsOnSubtractedFilters(t *testing.T) {
	t.Parallel()

	paths, err := sigmaFilesUnder(importedCorpus, "imported")
	require.NoError(t, err)

	users := 0
	for _, path := range paths {
		raw, readErr := importedCorpus.ReadFile(path)
		require.NoError(t, readErr)
		if bytes.Contains(raw, []byte("not 1 of filter_")) || bytes.Contains(raw, []byte("and not filter_")) {
			users++
		}
	}
	assert.Positive(t, users, "no imported rule subtracts a named filter, so the engine capability has no consumer")
	t.Logf("%d imported rules subtract a named filter", users)
}

// fieldsEvent is a literal sigma.Event, bypassing sigmabind, for evaluating a detection under a field supplier that is not ours.
type fieldsEvent map[string][]string

func (f fieldsEvent) Field(name string) ([]string, bool) { v, ok := f[name]; return v, ok }

// countingGraphReader records how many times a rule resolved the subject process, so a test can pin that it resolves once.
type countingGraphReader struct {
	perPIDGraphReader
	proc  *rulesapi.Process
	calls int
}

func (r *countingGraphReader) GetProcessByPID(_ context.Context, _ string, _ int, _ int64) (*rulesapi.Process, error) {
	r.calls++
	return r.proc, nil
}

// TestSudoersReadsTheSubjectProcessAtMostOnce pins that the writer is resolved once per event and that the finding names the same
// process the detection matched on.
//
// Two reads would not just cost more: a materialization commit landing between them could return a different image, so the
// suppression would be decided against one writer and the alert would name another. The condition can also short-circuit before it
// reads Image, so "the detection already resolved it" is not something the finding path can assume.
func TestSudoersReadsTheSubjectProcessAtMostOnce(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		flags     int
		writer    string
		wantFind  bool
		wantReads int
	}{
		{"a match resolves once and reuses it", 1537, "/usr/bin/tee", true, 1},
		// A lock never reaches the graph at all now. The adapter withholds TargetFilename for an open with no content-changing
		// bit (#801), so the path test fails before anything needs the writer. It used to cost one read, because the suppression
		// was a rule condition on Image and the rule had to resolve the writer to evaluate it.
		{"a lock never reads the graph", 1, "/usr/bin/sudo", false, 0},
		// The path test fails before anything needs the writer, so the graph is never touched.
		{"a non-sudoers path never reads the graph", 1537, "/usr/bin/tee", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := "/etc/sudoers"
			if tc.wantReads == 0 {
				path = "/etc/sudoers.d/nested/deeper" // matches the byte prefilter, fails the rule's path pattern
			}
			gr := &countingGraphReader{proc: &rulesapi.Process{ID: 42, PID: 7, Path: tc.writer}}
			rule := &SudoersTamper{}
			evt := rulesapi.Event{
				EventID: "e1", HostID: "h1", EventType: "open", TimestampNs: 1,
				Payload: []byte(fmt.Sprintf(`{"pid":7,"path":%q,"flags":%d}`, path, tc.flags)),
			}

			finding, err := rule.evalEvent(t.Context(), &rulesapi.BatchScope{}, evt, gr)
			require.NoError(t, err)
			assert.Equal(t, tc.wantReads, gr.calls, "graph reads")
			if !tc.wantFind {
				assert.Nil(t, finding)
				return
			}
			require.NotNil(t, finding)
			assert.Contains(t, finding.Description, tc.writer, "the finding names the process the detection matched on")
		})
	}
}
