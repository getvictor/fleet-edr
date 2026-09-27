#!/usr/bin/env bash
#
# Pre-pilot dogfood attack runbook.
#
# What this is
# ============
# A reproducible synthetic-attacker script that fires every shipped detection
# rule exactly once. Run on a host with the EDR agent installed + enrolled,
# then check the EDR admin UI for one alert per step. The script is
# explicitly NOT malicious: every step generates a benign artifact under
# /tmp or removes itself; nothing persists, nothing exfiltrates real data.
#
# Why each step looks like it does
# --------------------------------
# Every rule maps onto one step. The shape of the step is reverse-engineered
# from the rule's positive trigger (server/detection/rules/*.go) so that the
# alert fires on the agent without needing extension-side changes. That means
# some steps look contrived (e.g. building a tiny Go writer to satisfy the
# launchd-plist-write rule's "non-platform-binary" check). The contrivance
# is documented per step.
#
# How to run on the dev VM
# ------------------------
#   scp scripts/qa/attack-runbook.sh victor@192.168.64.5:/tmp/
#   ssh victor@192.168.64.5 'bash /tmp/attack-runbook.sh'
#
# Then watch alerts in the admin UI at <your-edr-url>/ui/alerts
# (whatever URL your server is reachable on: TLS for prod, plain HTTP
# is fine for the lab VM behind a closed network). Expected alert count
# is printed at the end.
#
# Prerequisites on the target host
# --------------------------------
#  - Fleet EDR agent enrolled and posting events.
#  - sudo for steps that need root (LaunchDaemon write, security
#    dump-keychain). Most steps work without sudo.
#  - Optional: `go` available to build the synthetic dropper (one rule
#    needs a non-platform-signed writer). Skipped with a warning if
#    missing.
#
# What this is NOT
# ----------------
#  - A penetration test. It does not chain steps to escalate privileges.
#  - A reliability harness. It is not idempotent in the sense that running
#    it twice in 60s might dedupe alerts via the engine's
#    (rule_id, host_id, process_id) uniqueness. That's normal. Wait a
#    minute between runs if you want fresh alerts.
#  - A fuzzer. The synthetic events are exact rule triggers.

set -uEo pipefail

# Strict mode minus -e: we want to keep going past a failed step so the
# operator gets a complete picture of which rules fired and which didn't.
# -E (errtrace) makes the trap inherit into shell functions; without it
# only top-level errors fire the trap and per-step failures stay silent.
# shellcheck disable=SC2154  # `rc` is assigned inside the trap body via $?
trap 'rc=$?; echo "[runbook] step at line $LINENO exited $rc - continuing"' ERR

# Pin WORKDIR to /tmp/ rather than $TMPDIR. As an unprivileged user $TMPDIR
# resolves to /var/folders/<gibberish>/T/, which is NOT in the suspicious_exec
# rule's prefix list: using it would silently render the synthetic_payload
# step a no-op against the rule. /tmp/ is what real droppers target on macOS
# and what the rule expects.
WORKDIR="/tmp/edr-attack-runbook"
mkdir -p "$WORKDIR"

EXPECTED_ALERTS=()

# skip_step records a step that could not run, in BOTH forms it needs to reach.
#
# The human line goes in the summary an operator reads after running this over SSH by hand, which is what this script is
# still for. The machine line is what scripts/uat/scenarios/attack-runbook/attack.sh greps so the L5 driver can tell an
# unrun attack from an undetected one: before it existed, an absent prerequisite surfaced as "miss: <rule>", which reads as
# the EDR failing to detect something that never happened, and cost real diagnosis time on the v0.5.0-rc.1 run (issue #965).
#
# Two lines rather than teaching the driver to parse the human one: the summary is prose meant to be reworded, and a parser
# reading it would break silently the next time someone improved the wording.
skip_step() {
  local rule_id="$1" reason="$2"
  echo "[runbook] SKIP rule_id=$rule_id reason=$reason"
  EXPECTED_ALERTS+=("$rule_id - SKIPPED ($reason)")
}

# Demo pacing: how long to pause between steps so a live audience can see each
# alert land in the UI before the next attack fires. 0 disables (lab use), 8
# is the right cadence for a live demo. Override with --pace=N or
# EDR_RUNBOOK_PACE_SECONDS=N.
PACE_SECONDS="${EDR_RUNBOOK_PACE_SECONDS:-0}"

# Total step count, used so the per-step header reads "Step 3 of 7" and the
# operator can call out matches live. Increment STEP each step.
TOTAL_STEPS=7
STEP=0

# Ascii separator between steps so the operator can scroll the SSH session.
hr() {
  printf '\n%s\n' '────────────────────────────────────────────────────────'
  return 0
}

# step_header prints a presenter-friendly banner: "Step N of M: <title>" with
# the expected rule_id beneath, so the operator can call out the match in real
# time. Bumps the global STEP counter as a side effect.
step_header() {
  STEP=$((STEP + 1))
  local title="$1" rule_id="$2"
  hr
  printf '[runbook] Step %d of %d: %s\n' "$STEP" "$TOTAL_STEPS" "$title"
  printf '[runbook]   expecting rule_id=%s in the alerts list\n' "$rule_id"
  return 0
}

# build_btm_dropper compiles the synthetic persistence dropper and prints its path. Built locally so the program it registers is
# ad-hoc signed by the linker, with no team and no Apple platform flag: the untrusted-executable case both BTM persistence rules
# fire on. Each call builds to its own unique path because BTM keys a launch item's identity on the registered executable path, and
# re-registering a path BTM already knows emits no fresh NOTIFY_BTM_LAUNCH_ITEM_ADD. So the daemon and agent steps each get their
# own binary, and every run gets new ones.
build_btm_dropper() {
  command -v go >/dev/null 2>&1 || return 1
  mkdir -p "$WORKDIR"
  local src="$WORKDIR/synthetic_dropper.go" bin
  bin="$WORKDIR/synthetic_dropper_$(date +%s)_$$_$RANDOM"
  cat > "$src" <<'GO'
package main

// Synthetic persistence dropper for the EDR runbook. `system` registers a LaunchDaemon (needs root) to exercise
// privilege_launchd_plist_write (T1543.004); `agent` registers a LaunchAgent in the invoking user's GUI domain to exercise
// persistence_launchagent (T1543.001). Either way the item runs this binary with `noop`, then is booted out and removed.
import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func main() {
	// When launchd actually launches the registered item it runs us with "noop"; return so we never recurse.
	if len(os.Args) < 2 || os.Args[1] == "noop" {
		return
	}
	// Unique label per run. BTM deduplicates at the source: re-registering a (label, executable) it already knows emits
	// no fresh ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, so a fixed label fires the rule only on the host's first-ever
	// run and silently no-ops afterwards. A per-run label also gives a unique alert subject (the item path) so the
	// server's (source, host, rule, subject) dedup does not collapse this run's alert onto a prior run's row, which
	// would fall outside the L5 driver's "alerts since scenario start" polling window.
	label := fmt.Sprintf("com.synthetic.edr-runbook.%d", time.Now().UnixNano())
	var dir, domain string
	switch os.Args[1] {
	case "system":
		dir, domain = "/Library/LaunchDaemons", "system"
	case "agent":
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("home directory: %v", err)
		}
		dir, domain = filepath.Join(home, "Library", "LaunchAgents"), fmt.Sprintf("gui/%d", os.Getuid())
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("create %s: %v", dir, err)
		}
	default:
		log.Fatalf("usage: %s system|agent", os.Args[0])
	}
	target := filepath.Join(dir, label+".plist")
	self, err := os.Executable()
	if err != nil {
		log.Fatalf("executable path: %v", err)
	}
	body := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>` + label + `</string>
  <key>ProgramArguments</key><array><string>` + self + `</string><string>noop</string></array>
</dict></plist>
`
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		log.Fatalf("write plist: %v", err)
	}
	// Register with launchd -> emits NOTIFY_BTM_LAUNCH_ITEM_ADD, the persistence signal. A refused bootstrap registers
	// nothing, so no alert can follow: cleanup still runs, and the exit status tells the runbook to skip the step rather
	// than count a detection miss.
	out, bootstrapErr := exec.Command("/bin/launchctl", "bootstrap", domain, target).CombinedOutput()
	if bootstrapErr != nil {
		log.Printf("bootstrap failed: %v: %s", bootstrapErr, out)
	}
	// BTM delivers NOTIFY_BTM_LAUNCH_ITEM_ADD asynchronously. Booting the item out in the same instant coalesces the
	// registration away before the kernel emits the ADD, so the extension never sees it (ground-truthed on edr-qa: a
	// back-to-back bootstrap+bootout produced no event, a bootstrap with a multi-second settle did). Let the ADD land
	// before cleaning up.
	time.Sleep(3 * time.Second)
	// Cleanup: unregister + remove so the host returns to a clean state.
	_ = exec.Command("/bin/launchctl", "bootout", domain+"/"+label).Run()
	if err := os.Remove(target); err != nil {
		log.Printf("cleanup remove: %v", err)
	}
	if bootstrapErr != nil {
		os.Exit(1)
	}
}
GO
  go build -o "$bin" "$src" >&2 || return 1
  printf '%s\n' "$bin"
}

# step_pace pauses for PACE_SECONDS so the live audience can watch the alert
# land in the UI before the next step fires. No-op when PACE_SECONDS=0.
step_pace() {
  if [[ "$PACE_SECONDS" -gt 0 ]]; then
    printf '[runbook]   waiting %ds for the alert to land in the UI...\n' "$PACE_SECONDS"
    sleep "$PACE_SECONDS"
  fi
  return 0
}

step_suspicious_exec() {
  step_header "Temp-path exec via non-shell parent" "suspicious_exec"
  # Rule trigger: a shell (/bin/sh / /bin/bash / /bin/zsh) whose PARENT is
  # NOT itself a shell forks a child under /tmp/* within 30s. The rule
  # explicitly skips shell→shell→/tmp chains (suspicious_exec.go:110), so
  # we cannot just call `/bin/sh -c "$payload"` from this bash script -
  # the runbook's bash would be the shell parent and the alert would
  # never fire. Use python3 as a non-shell launcher so the chain becomes
  # python3 → /bin/sh → /tmp/synthetic_payload.
  local payload="$WORKDIR/synthetic_payload"
  # Pre-create the file at mode 0700 in one step; the subsequent `cat >`
  # truncates and refills content but preserves mode, so the payload is
  # never visible to other users at any point.
  install -m 0700 /dev/null "$payload"
  cat > "$payload" <<'PAYLOAD'
#!/bin/sh
# Benign synthetic payload for EDR runbook. Does nothing.
echo "synthetic payload ran $(date -u)" >> "$0.log"
PAYLOAD
  if ! command -v python3 >/dev/null 2>&1; then
    skip_step suspicious_exec "no python3 on this host"
    return 0
  fi
  /usr/bin/env python3 -c "import subprocess; subprocess.Popen(['/bin/sh', '-c', '$payload && true']).wait()" || true
  EXPECTED_ALERTS+=("suspicious_exec - python3 → /bin/sh → $payload")
  return 0
}

step_persistence_launchagent() {
  step_header "LaunchAgent registration via BTM" "persistence_launchagent"
  # Rule trigger: ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD with item_type=agent, surfaced when launchd registers a LaunchAgent.
  # The rule judges the REGISTERED PROGRAM's signature, so the agent must run something that is not an Apple platform binary:
  # the locally built dropper (ad-hoc signed by the linker, no team) registers a per-run LaunchAgent in this user's GUI domain
  # pointing at itself, waits for the ADD to land, then boots it out and removes it. Nothing keeps running.
  local bin
  if ! bin="$(build_btm_dropper)"; then
    skip_step persistence_launchagent "could not build the BTM dropper (no Go toolchain, or the build failed)"
    return 0
  fi
  if ! "$bin" agent; then
    skip_step persistence_launchagent "launchd refused the LaunchAgent bootstrap (no GUI session for this user?)"
    return 0
  fi
  EXPECTED_ALERTS+=("persistence_launchagent: registered + removed LaunchAgent com.synthetic.edr-runbook via launchctl bootstrap gui/$(id -u)")
  return 0
}

step_dyld_insert() {
  step_header "DYLD library injection on exec" "dyld_insert"
  # Rule trigger: an exec event whose `args` array carries a leading
  # `DYLD_INSERT_LIBRARIES=` (or `DYLD_LIBRARY_PATH=`) assignment in a
  # position the rule treats as exec-time env (dyld_insert.go:matchDyldArg).
  # The rule's "VAR=val target" branch only sees the assignment when ESF
  # captures it in the exec's argv, and ESF only captures argv, NOT envp.
  # Shell prefix syntax (`DYLD_…=… /usr/bin/true`) puts the assignment in
  # envp, which the rule never sees, so the runbook MUST go through
  # `/usr/bin/env` to get the assignment into argv as a literal token.
  /usr/bin/env DYLD_INSERT_LIBRARIES=/tmp/synthetic-not-a-real-dylib.dylib /usr/bin/true || true
  EXPECTED_ALERTS+=("dyld_insert - /usr/bin/env DYLD_INSERT_LIBRARIES=... /usr/bin/true")
  return 0
}

step_osascript_network_exec() {
  step_header "AppleScript-driven download-and-exec chain" "osascript_network_exec"
  # Rule trigger: osascript spawns a process tree containing both a
  # curl/wget descendant AND a downstream exec whose path is under /tmp/
  # within 30s. The rule keys on the EXEC event for the /tmp/* binary,
  # not on the curl response, so we MUST actually run a binary that
  # lives in /tmp (curl writing to /tmp is not enough; the file has to
  # be exec'd). Pre-create a benign stage2 binary so the chain has the
  # /tmp/* exec the rule needs, then have osascript invoke both curl
  # (kept harmless via 127.0.0.1:9) and the pre-staged binary.
  local stage2="/tmp/synthetic_stage2"
  # See step_suspicious_exec for the install + truncate-write rationale.
  install -m 0700 /dev/null "$stage2"
  cat > "$stage2" <<'STAGE2'
#!/bin/sh
# Benign synthetic stage2 for EDR runbook. Does nothing.
echo "synthetic stage2 ran $(date -u)" >> "$0.log"
STAGE2
  /usr/bin/osascript -e "do shell script \"/usr/bin/curl -m 2 -o /dev/null http://127.0.0.1:9/edr-runbook-synthetic 2>/dev/null; $stage2\"" 2>/dev/null || true
  EXPECTED_ALERTS+=("osascript_network_exec - osascript → (curl + $stage2)")
  return 0
}

step_credential_keychain_dump() {
  step_header "Keychain credential dump attempt" "credential_keychain_dump"
  # Rule trigger: exec of /usr/bin/security with "dump-keychain" as the
  # first non-flag argv token. Run with stdin redirected from /dev/null so
  # the binary fails immediately on the password prompt rather than
  # hanging. Rule fires on exec regardless of dump success.
  /usr/bin/security dump-keychain </dev/null >/dev/null 2>&1 || true
  EXPECTED_ALERTS+=("credential_keychain_dump - /usr/bin/security dump-keychain")
  return 0
}

step_privilege_launchd_plist_write() {
  step_header "LaunchDaemon registration via BTM" "privilege_launchd_plist_write"
  # Rule trigger (ADR-0008): ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD with item_type=daemon, surfaced when launchd
  # registers a system LaunchDaemon. We write a plist into /Library/LaunchDaemons, `launchctl bootstrap` it (the BTM
  # trigger), then bootout + remove it. The daemon's executable is this locally-built, non-Apple binary, run with a
  # `noop` arg so launchd launching it cannot recurse.
  #
  # IMPORTANT: BTM fires at REGISTRATION, not at the file write: a plain write+remove (the pre-ADR-0008 behaviour) no
  # longer triggers detection. The rule keys on the REGISTERED EXECUTABLE's code-signing, not the instigator (the BTM
  # instigator for a `launchctl bootstrap` is Apple's smd, ground-truthed on edr-dev), so this locally-built, unsigned
  # daemon executable fires regardless of the platform-binary instigator (see ADR-0008 and its 2026-05-29 amendment).
  local bin
  if ! bin="$(build_btm_dropper)"; then
    skip_step privilege_launchd_plist_write "could not build the BTM dropper (no Go toolchain, or the build failed)"
    return 0
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "[runbook] this step needs root to register a LaunchDaemon; trying sudo -n"
    # -n (non-interactive) bails immediately when sudo would otherwise prompt for a password. The runbook runs over SSH
    # (`ssh victor@... 'bash /tmp/attack-runbook.sh'`), so an interactive prompt would deadlock the whole script.
    if ! sudo -n true 2>/dev/null; then
      skip_step privilege_launchd_plist_write "no NOPASSWD sudo for the dropper (see scripts/uat/README.md)"
      return 0
    fi
    if ! sudo -n "$bin" system; then
      skip_step privilege_launchd_plist_write "launchd refused the LaunchDaemon bootstrap"
      return 0
    fi
  elif ! "$bin" system; then
    skip_step privilege_launchd_plist_write "launchd refused the LaunchDaemon bootstrap"
    return 0
  fi
  EXPECTED_ALERTS+=("privilege_launchd_plist_write: registered + removed LaunchDaemon com.synthetic.edr-runbook via launchctl bootstrap")
  return 0
}

step_shell_from_office_note() {
  step_header "Office-spawned shell (informational; not exercised)" "shell_from_office"
  # The rule keys on /Applications/Microsoft <App>.app/Contents/MacOS/<App>
  # as the parent process, with /bin/{sh,bash,zsh} as the child within 30s.
  # Office isn't installed on the dev VM. The plan calls out spoofing this
  # chain via the Swift test harness; that's tracked separately. Listed
  # here so the runbook output makes the deliberate omission explicit
  # rather than silently leaving operators wondering.
  EXPECTED_ALERTS+=("shell_from_office - INTENTIONALLY NOT exercised (no Office on the VM)")
  return 0
}

parse_args() {
  for arg in "$@"; do
    case "$arg" in
      --pace=*) PACE_SECONDS="${arg#--pace=}" ;;
      --demo)   PACE_SECONDS=8 ;;
      --help|-h)
        cat <<USAGE
Usage: $0 [--pace=N | --demo]
  --pace=N   Sleep N seconds between steps so an audience can watch each
             alert land in the UI before the next attack fires. Default 0.
  --demo     Shorthand for --pace=8 (the default live-demo cadence).

Or set EDR_RUNBOOK_PACE_SECONDS=N in the environment.
USAGE
        exit 0 ;;
      *) echo "[runbook] unknown argument: $arg" >&2; exit 2 ;;
    esac
  done
  # Validate PACE_SECONDS up-front. The downstream `[[ "$PACE_SECONDS" -gt 0 ]]`
  # and `sleep "$PACE_SECONDS"` calls will explode mid-script on a non-integer
  # (the trap fires "step at line N exited 2" and a confused operator wonders
  # why nothing fired). Reject early with a clear message instead.
  if ! [[ "$PACE_SECONDS" =~ ^[0-9]+$ ]]; then
    echo "[runbook] invalid PACE_SECONDS=\"$PACE_SECONDS\" - must be a non-negative integer" >&2
    exit 2
  fi
  return 0
}

main() {
  parse_args "$@"
  echo "[runbook] Fleet EDR synthetic attacker - $(date -u)"
  echo "[runbook] working dir: $WORKDIR"
  if [[ "$PACE_SECONDS" -gt 0 ]]; then
    echo "[runbook] live-demo pacing: ${PACE_SECONDS}s between steps"
  fi
  step_suspicious_exec;        step_pace
  step_persistence_launchagent; step_pace
  step_dyld_insert;            step_pace
  step_osascript_network_exec; step_pace
  step_credential_keychain_dump; step_pace
  step_privilege_launchd_plist_write; step_pace
  step_shell_from_office_note
  hr
  echo "[runbook] Done. Expected alerts in the admin UI:"
  for a in "${EXPECTED_ALERTS[@]}"; do
    echo "  - $a"
  done
  hr
  echo "[runbook] Verify in the admin UI:"
  echo "    open '<your-edr-url>/ui/alerts'"
  echo "[runbook] Cleanup: rm -rf $WORKDIR (/Library/LaunchDaemons drop is removed by the dropper itself)"
  return 0
}

main "$@"
