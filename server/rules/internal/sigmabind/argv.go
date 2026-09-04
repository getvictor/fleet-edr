package sigmabind

import "strings"

// Computed argv fields.
//
// Sigma matches fields, not argument vectors: CommandLine is one string, so every trace of which POSITION a token occupied is gone
// by the time a rule sees it. Three of our detections turn on exactly that position, which is why converting them to
// `CommandLine|contains` silently widens them (issue #761). Measured against the fixtures the Go rule is already pinned to,
// `Image|endswith: '/security'` plus `CommandLine|contains: 'dump-keychain'` fires on `security help dump-keychain`, which the Go
// rule deliberately does not.
//
// So the positional facts are computed here and matched as ordinary fields, which is the approach ADR/epic #756 settled on: "where
// a native predicate is tempting, compute it at ingest and match it as a field, the way Sysmon precomputes Hashes and
// OriginalFileName". A rule using one of these is `portable: mapped` rather than `standard`: still valid Sigma, but it needs a
// field only we supply.

// subcommand returns the verb a command-line tool will act on: the first non-flag token after argv[0].
//
// argv[0] is the invocation name rather than an argument. Tokens starting with `-` are flags, so `security -v dump-keychain` still
// yields dump-keychain. The first non-flag token DECIDES: `security help dump-keychain` yields "help", not "dump-keychain", which is
// the whole point, since `security` will act on `help` and never read a keychain.
//
// An empty token counts as the subcommand rather than being skipped. `security "" dump-keychain` therefore yields "", so a rule
// keyed on a real subcommand does not fire, which is right: the tool would reject the empty verb and never act on the later token.
// This is the safe direction, since it can only make a rule fire less. It matches the keychain rule's pre-conversion matcher,
// frozen as legacyFindDumpKeychainArg in the equivalence test, and differs from the launch-agent rule's
// pre-conversion matcher, whose empty-skip was an artifact of using "" as its not-found sentinel rather than a decision.
//
// Known limitation, inherited from the Go rules rather than introduced here: a flag that takes a SEPARATE value has that value
// mistaken for the subcommand, so `sudo -S -p "" cp` yields "" rather than "cp". That shape is real (59 of 669,428 exec events on a
// dev host, every one of them `sudo -p ""`), but it does not reach the tools this serves: neither `security` nor `launchctl` takes a
// value-bearing flag ahead of its verb. A tool that does would need its own field rather than this one.
func subcommand(argv []string) string {
	for i, a := range argv {
		if i == 0 {
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// commandArguments returns the operands that follow the subcommand: every non-flag, non-empty token after it.
//
// List-valued, because Sigma matches a list-valued field when ANY element matches, which is exactly the question the launch-agent
// rule asks: "is one of the later arguments a LaunchAgent plist path". Flags are skipped so `launchctl load -w /path/x.plist` still
// offers /path/x.plist. Empty tokens are dropped because they carry no information and cannot match any pattern.
func commandArguments(argv []string) []string {
	var out []string
	seenSubcommand := false
	for i, a := range argv {
		if i == 0 || strings.HasPrefix(a, "-") {
			continue
		}
		if !seenSubcommand {
			seenSubcommand = true
			continue
		}
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

// envAssignments returns the environment assignments made at exec time that are visible in argv, as KEY=VALUE tokens.
//
// The window is deliberately narrow, because an assignment is only an assignment in the leading position:
//
//   - For an `env`-style invocation (the binary is /usr/bin/env or any path ending in /env), it is the run of tokens that contain
//     "=" AFTER env's own options, ending at the first token that does not. `env A=1 B=2 prog C=3` yields A=1 and B=2 but not C=3,
//     which is correct: C=3 is an argument to prog, not an assignment env performs.
//
//     The option prefix is parsed rather than treated as the end of the run (issue #792). `env -i DYLD_INSERT_LIBRARIES=x /bin/true`
//     is a real injection whose assignment used to be invisible, because `-i` contains no "=" and ended the scan before it. The
//     same held for `-u NAME`, `-P path`, `-S string` and anything after `--`.
//
//   - For anything else it is argv[0] alone, which is the shell's `VAR=value cmd` form as the dyld_insert rule describes it.
//     Worth knowing: that branch appears to be unreachable in practice. ESF serialises only es_exec_arg, so the environment a shell
//     applies is never in argv, and argv[0] is an assignment in 0 of 670,185 real exec events on a dev host. The branch is
//     reproduced here because this field's contract is to match the Go matcher exactly; issue #791 covers the rule.
//
// This is what makes the field worth computing. `DYLD_INSERT_LIBRARIES=x /bin/true` and `/bin/true DYLD_INSERT_LIBRARIES=x` join to
// DIFFERENT CommandLine strings, since argv is joined in order, but they carry the same assignment text and only the first is an
// injection. A rule written as `CommandLine|contains: 'DYLD_INSERT_LIBRARIES='` matches both, because a substring match is exactly
// the operation that discards position.
//
// The window is decided by the resolved executable path rather than by argv[0], since argv[0] is whatever the caller chose to pass.
func envAssignments(path string, argv []string) []string {
	if path != "/usr/bin/env" && !strings.HasSuffix(path, "/env") {
		// Not env: the window is argv[0] alone, the shell's `VAR=value cmd` form.
		if len(argv) > 0 && isAssignment(argv[0]) {
			return []string{argv[0]}
		}
		return nil
	}

	// argv[0] is the program name env was invoked as, never an option or an assignment, so option parsing starts after it.
	if len(argv) == 0 {
		return nil
	}
	after, usable := skipEnvOptions(argv[1:])
	if !usable {
		// Either env would have refused these options and run nothing, or the run that follows them says nothing about what env
		// applied. Both mean there is no assignment here to report.
		return nil
	}

	var out []string
	for _, a := range argv[min(1+after, len(argv)):] {
		if !strings.Contains(a, "=") {
			// The run ends at the first token that assigns nothing, which is the command env will run.
			//
			// The boundary is "contains a separator", NOT the stricter isAssignment below, and the difference is a bypass. env
			// accepts any nonempty name, so `env 2+2=4 DYLD_INSERT_LIBRARIES=x prog` really does apply both; breaking on the
			// first token a SHELL would reject truncates the run and hides the injection behind it. Review pushed this both ways,
			// and the direction that matters is the one that cannot miss a real assignment: end the run late, and let the filter
			// below decide what is worth reporting.
			break
		}
		if isAssignment(a) {
			out = append(out, a)
		}
	}
	return out
}

// env's short options, grouped by how each one affects the assignment run that follows it. Taken from env(1) on macOS and
// verified by running it, because every one of these groups was got wrong at least once by reasoning alone.
//
// Getting a group wrong is a detection error in one direction or the other. An operand mistaken for an assignment reports
// `env -u DYLD_INSERT_LIBRARIES prog` as an injection when it is the exact opposite, an unset. An option whose operand is missed
// ends the scan early and hides the assignment behind it.
const (
	// Options whose value may be a separate argument: -u name, -P utilpath, -S string, -C workdir.
	envOptionsTakingAnOperand = "uPSC"
	// Options that take no value: -i, -v.
	envOptionsTakingNone = "iv"
	// Options after which the outer argument vector no longer describes what env applied to a command.
	//
	// -0 because env REFUSES to run a command at all with it (`env -0 A=1 /bin/sh` exits `cannot specify command with -0`), so
	// nothing was injected into anything. -S because its operand is a whole command line that env re-splits, and the split
	// payload may itself name the command: `env -S "/bin/echo hi" DYLD_INSERT_LIBRARIES=/tmp/x` runs echo with the assignment
	// as its ARGUMENT, which measurement confirms, so reporting it as an assignment would be a fabricated injection finding.
	envOptionsEndingTheRun = "0S"
)

// skipEnvOptions returns the index of env's first non-option argument, and whether the assignment run that starts there describes
// anything env actually applied.
//
// usable is false for three distinct reasons that the caller treats identically, which is why they share one flag rather than an
// enum the caller would only collapse again:
//
//   - An option env does not have. env exits without executing the command, so no assignment it carries was ever applied:
//     `env -z DYLD_INSERT_LIBRARIES=x prog` injects nothing because env never execs prog.
//   - -0, which env refuses to combine with a command at all.
//   - -S, whose payload governs the command line and which this parser deliberately does not re-split.
//
// In all three the safe direction is the same and it is not symmetric: reporting nothing risks MISSING an injection, while
// reporting the run risks FABRICATING one against a high-severity rule. A miss is recoverable by another detection; a fabricated
// dylib-injection finding sends an analyst after an event that did not happen.
//
// Clustering follows BSD env. An operand-taking letter consumes the REST of its own token when there is any (`-uNAME`, and also
// `-uS`, where S is the name and not a second option), and the next argument otherwise (`-u NAME`, `-iu NAME`). A lone dash means
// the same as -i and takes no operand.
func skipEnvOptions(argv []string) (next int, usable bool) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			return i + 1, true
		case a == "-":
			i++
		case len(a) > 1 && a[0] == '-':
			consumed, ok := parseEnvOptionCluster(a[1:])
			if !ok {
				return 0, false
			}
			i++
			if consumed {
				i++
			}
		default:
			return i, true
		}
	}
	return i, true
}

// parseEnvOptionCluster walks one cluster's letters, reporting whether it consumes the NEXT argument as an operand and whether the
// assignment run after the cluster is still meaningful.
func parseEnvOptionCluster(letters string) (consumesNext, usable bool) {
	for k := range len(letters) {
		c := rune(letters[k])
		switch {
		case strings.ContainsRune(envOptionsEndingTheRun, c):
			// Reached before the operand check on purpose, since -S is in both sets and its payload is what makes the run
			// meaningless. Whether the payload is attached or separate makes no difference to that.
			return false, false
		case strings.ContainsRune(envOptionsTakingAnOperand, c):
			// The operand is whatever remains of this token, or the next argument when nothing remains.
			return k == len(letters)-1, true
		case strings.ContainsRune(envOptionsTakingNone, c):
			continue
		default:
			return false, false
		}
	}
	return false, true
}

// isAssignment reports whether a token is a real KEY=VALUE assignment rather than merely containing "=".
//
// A token such as `=VALUE` or `2+2=4` contains "=" and is not an assignment, and admitting it would let a future rule match on
// something the shell never assigned. This is behaviour-neutral for the rule this field serves today, since every DYLD_ prefix it
// looks for carries a valid key, so narrowing here cannot drop a token the Go matcher would have matched.
func isAssignment(token string) bool {
	key, _, found := strings.Cut(token, "=")
	if !found || key == "" {
		return false
	}
	for i, r := range key {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
		isDigitAfterFirst := i > 0 && r >= '0' && r <= '9'
		if !isLetter && !isDigitAfterFirst {
			return false
		}
	}
	return true
}
