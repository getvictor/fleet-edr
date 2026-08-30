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
// This is the safe direction, since it can only make a rule fire less. It matches findDumpKeychainArg, and differs from
// extractLaunchctlSubcommand, whose empty-skip is an artifact of using "" as its not-found sentinel rather than a decision.
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
//   - For an `env`-style invocation (the binary is /usr/bin/env or any path ending in /env), it is the run of leading tokens that
//     contain "=", ending at the first token that does not. `env A=1 B=2 prog C=3` yields A=1 and B=2 but not C=3, which is correct:
//     C=3 is an argument to prog, not an assignment env performs.
//   - For anything else it is argv[0] alone, the shell's `VAR=value cmd` form.
//
// This is what makes the field worth computing. `DYLD_INSERT_LIBRARIES=x /bin/true` and `/bin/true DYLD_INSERT_LIBRARIES=x` produce
// the same CommandLine, and only the first is an injection; a rule matching the joined string cannot tell them apart.
//
// The window is decided by the resolved executable path rather than by argv[0], since argv[0] is whatever the caller chose to pass.
func envAssignments(path string, argv []string) []string {
	envStyle := path == "/usr/bin/env" || strings.HasSuffix(path, "/env")
	var out []string
	for i, a := range argv {
		if i > 0 && !envStyle {
			break
		}
		if i > 0 && !strings.Contains(a, "=") {
			break
		}
		if strings.Contains(a, "=") {
			out = append(out, a)
		}
	}
	return out
}
