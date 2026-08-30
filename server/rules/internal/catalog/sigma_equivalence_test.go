package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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

func legacyMatchDyldArg(path string, args []string) string {
	isEnv := path == "/usr/bin/env" || strings.HasSuffix(path, "/env")
	for i, a := range args {
		if !isEnv && i > 0 {
			break
		}
		if isEnv && i > 0 && !strings.Contains(a, "=") {
			break
		}
		for _, prefix := range legacyDyldPrefixes {
			if strings.HasPrefix(a, prefix) {
				return prefix + "<redacted>"
			}
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

// TestEquivalence_DyldInsert: as above, across both env-style and ordinary binaries.
func TestEquivalence_DyldInsert(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		path := rapid.SampledFrom([]string{"/usr/bin/env", "/opt/homebrew/bin/env", "/bin/sh", "/usr/bin/true"}).Draw(t, "path")
		argv := drawArgv(t)
		goFires := legacyMatchDyldArg(path, argv) != ""
		sigmaFires := evalCompiled(t, dyldDetection(), path, argv)
		require.Equal(t, goFires, sigmaFires, "path=%q argv=%q", path, argv)
	})
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
	require.Empty(t, legacyMatchDyldArg("/usr/bin/true", []string{"dyld_insert_libraries=/tmp/x"}))
	require.False(t, evalCompiled(t, dyldDetection(), "/usr/bin/true", []string{"dyld_insert_libraries=/tmp/x"}))
	require.NotEmpty(t, legacyMatchDyldArg("/usr/bin/true", []string{"DYLD_INSERT_LIBRARIES=/tmp/x"}))
	require.True(t, evalCompiled(t, dyldDetection(), "/usr/bin/true", []string{"DYLD_INSERT_LIBRARIES=/tmp/x"}))

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
			require.True(t, evalCompiled(t, dyldDetection(), "/usr/bin/true", []string{prefix + "/tmp/x"}),
				"the detection must fire on %q, or a finding built from it would name nothing", prefix)
		}
	})

	t.Run("the detection matches nothing dyldPrefixes cannot name", func(t *testing.T) {
		t.Parallel()
		// A variable the detection accepts but the slice does not would produce a finding with an empty variable name.
		for _, candidate := range []string{"DYLD_FRAMEWORK_PATH=", "DYLD_FALLBACK_LIBRARY_PATH=", "DYLD_PRINT_LIBRARIES="} {
			if !evalCompiled(t, dyldDetection(), "/usr/bin/true", []string{candidate + "/tmp/x"}) {
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

// TestEquivalence_SudoersTamper compares the shipped detection against the frozen oracle across paths, flag combinations and
// writers. The flag space is chosen deliberately: read-only, write-without-intent (sudo's flock shape), and write-with-intent are
// the three cases the rule distinguishes, and the third condition only bites on one writer.
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

					require.Equal(t, legacySudoersFires(path, flags, subject), sudoersDetection().Matches(ev))
				})
			}
		}
	}
	assert.Equal(t, len(paths)*len(flagSets)*len(subjects), checked, "every combination must be exercised")
}

// TestSudoersFlagChecksAreVestigialForCurrentAgents records what the conversion preserved and why it currently changes nothing.
//
// Since #301 (2026-05-31) the only source of `open` events is FileTamperSubscriber, which re-emits NOTIFY_CREATE and NOTIFY_WRITE
// on /etc/sudoers* with a CONSTANT synthetic flag set, `O_WRONLY|O_CREAT|O_TRUNC`. Against that constant both flag tests are
// no-ops: write access is always set, and the mutating bits are always set so the sudo suppression can never fire.
//
// The logic is kept because an agent predating #301 sends real open(2) flags, and dropping the tests would make a read-only open of
// /etc/sudoers on such a host start alerting. This test is the record of that reasoning, so a later reader can retire the fields
// deliberately once those agents are gone rather than discovering the masks look pointless and guessing. Tracked as #801.
func TestSudoersFlagChecksAreVestigialForCurrentAgents(t *testing.T) {
	t.Parallel()

	const synthetic = 0x1 | 0x200 | 0x400 // what FileTamperSubscriber emits, verified against captured telemetry as flags=1537
	require.Equal(t, 1537, synthetic)

	assert.NotZero(t, synthetic&legacySudoersWriteMask, "write access is always set, so that test always passes")
	assert.NotZero(t, synthetic&legacySudoersIntent, "the mutating bits are always set, so the sudo suppression can never fire")

	// And so sudo writing a sudoers file DOES alert today, where with real flock flags it would not.
	assert.True(t, legacySudoersFires("/etc/sudoers", synthetic, "/usr/bin/sudo"))
	assert.False(t, legacySudoersFires("/etc/sudoers", 0x1, "/usr/bin/sudo"), "the suppression still works on real flags")
}

// fieldsEvent is a literal sigma.Event, bypassing sigmabind. It exists to evaluate the shipped detection under a DIFFERENT field
// supplier than ours, which is the situation `portable: mapped` describes.
type fieldsEvent map[string][]string

func (f fieldsEvent) Field(name string) ([]string, bool) { v, ok := f[name]; return v, ok }

// TestSudoersRuleIsSelfContainedForOtherEngines pins the one thing the equivalence property structurally cannot see.
//
// Our adapter supplies TargetFilename only when the open carries write access, so against sigmabind the rule's `WriteIntent: true`
// is redundant and removing it does not change a single verdict (verified: that mutation survives TestEquivalence_SudoersTamper).
// It is NOT redundant for the exported rule. `portable: mapped` promises another engine can evaluate this rule given the mapped
// fields, and an engine that supplies TargetFilename on every open, as a literal reading of the Sigma taxonomy would, needs the
// rule itself to say it only wants writes. So the guard has a real consumer and is not the speculative kind.
func TestSudoersRuleIsSelfContainedForOtherEngines(t *testing.T) {
	t.Parallel()

	// A read-only open of /etc/sudoers, from an engine that does not gate TargetFilename on write access.
	readOnly := fieldsEvent{"TargetFilename": {"/etc/sudoers"}, "WriteIntent": {"false"}, "MutatingOpen": {"false"}, "Image": {"/bin/cat"}}
	assert.False(t, sudoersDetection().Matches(readOnly), "the rule must reject a read-only open on its own terms, not ours")

	writing := fieldsEvent{"TargetFilename": {"/etc/sudoers"}, "WriteIntent": {"true"}, "MutatingOpen": {"true"}, "Image": {"/bin/cp"}}
	assert.True(t, sudoersDetection().Matches(writing))
}

// spec:server-detection-rules-engine/a-rule-suppresses-a-named-exception-rather-than-branching-on-the-writer/the-suppression-applies-only-to-the-writer-it-names
//
// TestSudoersSuppressionIsScopedToSudo pins the half of the rule that a single write-intent boolean could not carry: the flock
// exception applies to sudo and to nothing else. Any other process performing the identical open still fires, which is what stops
// the exception from becoming a way to write a sudoers file unnoticed.
func TestSudoersSuppressionIsScopedToSudo(t *testing.T) {
	t.Parallel()

	const flockShape = 0x1 // O_WRONLY, no content-changing bit: write access with nothing written

	cases := []struct {
		name    string
		subject string
		want    bool
	}{
		{"sudo taking its lock is suppressed", "/usr/bin/sudo", false},
		{"tee performing the identical open fires", "/usr/bin/tee", true},
		{"a copy of sudo elsewhere on disk fires", "/tmp/sudo", true},
		// The detection matches, which is the honest answer for a filter that cannot confirm the writer is sudo. The rule then
		// produces no finding anyway, because evalEvent needs the process row to attach one to.
		{"an unresolved writer is not suppressed", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev, err := sigmabind.NewOpenEventLazy(
				rulesapi.Event{EventID: "e", EventType: "open",
					Payload: []byte(fmt.Sprintf(`{"pid":7,"path":"/etc/sudoers","flags":%d}`, flockShape))},
				func() (string, error) { return tc.subject, nil })
			require.NoError(t, err)
			assert.Equal(t, tc.want, sudoersDetection().Matches(ev))
		})
	}

	// And sudo is suppressed only for the flock shape: sudo truncating the file is a real edit and still fires.
	ev, err := sigmabind.NewOpenEventLazy(
		rulesapi.Event{EventID: "e", EventType: "open", Payload: []byte(`{"pid":7,"path":"/etc/sudoers","flags":1537}`)},
		func() (string, error) { return "/usr/bin/sudo", nil })
	require.NoError(t, err)
	assert.True(t, sudoersDetection().Matches(ev), "the exception is the lock, not the identity")
}

// countingGraphReader counts GetProcessByPID calls so a test can assert how many graph reads a rule performs. It embeds the
// package's existing full stub so it tracks the GraphReader interface rather than re-listing every method.
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
		{"a suppressed open resolves once", 1, "/usr/bin/sudo", false, 1},
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

			finding, err := rule.evalEvent(t.Context(), evt, gr)
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

// TestBooleanDetectionValuesAreYAMLBooleans pins that a boolean-valued field is emitted as a YAML boolean rather than a quoted
// string.
//
// Our evaluator cannot tell the difference: scalarString sends a bool through strconv.FormatBool, so `true` and 'true' match
// identically here and no behavioural test can catch a regression. The distinction matters to the promise `portable: mapped`
// makes. Sigma tooling preserves scalar types, so a backend that supplies WriteIntent as a real boolean and type-checks the
// comparison would not match a rule asking for the string "true", and the rule would silently never fire on that engine.
//
// The walk mirrors compileSearch: a search is a field map, or a LIST of field maps that are OR alternatives. Checking only the
// first form would leave a quoted boolean inside an alternative undetected, which is the shape a rule reaches for as soon as it
// needs "either of these two writers".
func TestBooleanDetectionValuesAreYAMLBooleans(t *testing.T) {
	t.Parallel()

	// The fields this engine computes as booleans. A rule may legitimately match the literal string "true" on some other field,
	// so this is scoped to the ones we know are boolean rather than to anything that looks like one.
	booleanFields := map[string]bool{"WriteIntent": true, "MutatingOpen": true}

	type boolCase struct {
		name  string // pack file, search, and field: the subtest name
		value any
	}

	entries, err := packFS.ReadDir("pack")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	// The table is built synchronously so "did the walk find anything" is answered before any subtest runs. Accumulating it
	// inside parallel subtests would read zero, because a parallel subtest returns before its body executes.
	var cases []boolCase
	// Mirrors scalarList: a field's value is a scalar, or a LIST of values that are OR alternatives. Asserting on the slice
	// itself would reject a legitimate `WriteIntent: [true, false]`, so each element becomes its own case.
	collect := func(file, where string, fields map[string]any) {
		for field, value := range fields {
			if !booleanFields[strings.SplitN(field, "|", 2)[0]] {
				continue
			}
			base := fmt.Sprintf("%s/%s.%s", file, where, field)
			if values, ok := value.([]any); ok {
				for i, element := range values {
					cases = append(cases, boolCase{name: fmt.Sprintf("%s[%d]", base, i), value: element})
				}
				continue
			}
			cases = append(cases, boolCase{name: base, value: value})
		}
	}
	for _, entry := range entries {
		body, err := packFS.ReadFile("pack/" + entry.Name())
		require.NoError(t, err)

		var file struct {
			Detection map[string]any `yaml:"detection"`
		}
		require.NoError(t, yaml.Unmarshal(body, &file))

		for searchName, search := range file.Detection {
			switch v := search.(type) {
			case map[string]any:
				collect(entry.Name(), searchName, v)
			case []any:
				// OR alternatives. Each entry the compiler accepts is a field map; anything else it refuses at load, so this
				// test does not need to re-report it.
				for i, alternative := range v {
					if fields, ok := alternative.(map[string]any); ok {
						collect(entry.Name(), fmt.Sprintf("%s[%d]", searchName, i), fields)
					}
				}
			}
			// Anything else is the condition string.
		}
	}
	require.NotEmpty(t, cases, "no boolean fields found, so this test would prove nothing")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.IsType(t, false, tc.value,
				"%s must be a YAML boolean, not %T: quoting it breaks a type-checking Sigma backend", tc.name, tc.value)
		})
	}
}
