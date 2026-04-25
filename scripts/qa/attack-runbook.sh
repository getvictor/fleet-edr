#!/usr/bin/env bash
#
# Phase-7 dogfood attack runbook (issue: claude/mvp/phase-7-pilot-hardening.md E1).
#
# What this is
# ============
# A reproducible synthetic-attacker script that fires every shipped detection
# rule exactly once. Run on a host with the EDR agent installed + enrolled,
# then check the EDR admin UI for one alert per step. The script is
# explicitly NOT malicious — every step generates a benign artifact under
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
# Then watch alerts in the admin UI at http://192.168.64.5:8088/ui/alerts
# (or wherever the server runs). Expected alert count is printed at the end.
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
#    (rule_id, host_id, process_id) uniqueness — that's normal. Wait a
#    minute between runs if you want fresh alerts.
#  - A fuzzer. The synthetic events are exact rule triggers.

set -uo pipefail

# Strict mode minus -e: we want to keep going past a failed step so the
# operator gets a complete picture of which rules fired and which didn't.
# shellcheck disable=SC2154  # `rc` is assigned inside the trap body via $?
trap 'rc=$?; echo "[runbook] step at line $LINENO exited $rc — continuing"' ERR

WORKDIR="${TMPDIR:-/tmp}/edr-attack-runbook"
mkdir -p "$WORKDIR"

EXPECTED_ALERTS=()

# Ascii separator between steps so the operator can scroll the SSH session.
hr() { printf '\n%s\n' '────────────────────────────────────────────────────────'; }

step_suspicious_exec() {
  hr
  echo "[runbook] suspicious_exec — shell parent → /tmp/<binary> child"
  # Rule trigger: a shell ( /bin/sh / /bin/bash / /bin/zsh ) forks a child
  # whose path is under /tmp/, /var/tmp/, or /private/tmp/ within 30s. Drop
  # an executable into /tmp and run it via the shell.
  local payload="$WORKDIR/synthetic_payload"
  cat > "$payload" <<'PAYLOAD'
#!/bin/sh
# Benign synthetic payload for EDR runbook. Does nothing.
echo "synthetic payload ran $(date -u)" >> "$0.log"
PAYLOAD
  chmod +x "$payload"
  /bin/sh -c "$payload" || true
  EXPECTED_ALERTS+=("suspicious_exec — /bin/sh child execed $payload")
}

step_persistence_launchagent() {
  hr
  echo "[runbook] persistence_launchagent — launchctl load on a fake plist"
  # Rule trigger: exec of `launchctl load <plist>` where plist matches
  # ~/Library/LaunchAgents/<name>.plist or /Library/LaunchAgents/<name>.plist.
  # We DO NOT actually persist anything — the plist is a syntactic
  # placeholder; launchctl will fail to load it (missing executable). The
  # rule fires on the EXEC of launchctl load, not on activation success.
  local plist_dir="$HOME/Library/LaunchAgents"
  local plist_path="$plist_dir/com.synthetic.edr-runbook.plist"
  mkdir -p "$plist_dir"
  cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.synthetic.edr-runbook</string>
  <key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
  <key>RunAtLoad</key><false/>
</dict></plist>
EOF
  /bin/launchctl load "$plist_path" >/dev/null 2>&1 || true
  /bin/launchctl unload "$plist_path" >/dev/null 2>&1 || true
  rm -f "$plist_path"
  EXPECTED_ALERTS+=("persistence_launchagent — launchctl load $plist_path")
}

step_dyld_insert() {
  hr
  echo "[runbook] dyld_insert — exec with DYLD_INSERT_LIBRARIES= argv prefix"
  # Rule trigger: exec event whose argv[0..N] contains a leading
  # "DYLD_INSERT_LIBRARIES=..." token. Note this requires SIP disabled OR
  # the target binary to be unsigned/non-restricted; on edr-dev (SIP off)
  # /usr/bin/true accepts the env injection. On edr-qa (SIP on) the env
  # is stripped, but the EXEC event still records the argv prefix that the
  # rule reads — so the alert fires regardless.
  DYLD_INSERT_LIBRARIES=/tmp/synthetic-not-a-real-dylib.dylib /usr/bin/true || true
  EXPECTED_ALERTS+=("dyld_insert — DYLD_INSERT_LIBRARIES prefix on /usr/bin/true")
}

step_osascript_network_exec() {
  hr
  echo "[runbook] osascript_network_exec — osascript → curl → /tmp/<file>"
  # Rule trigger: osascript spawns a curl/wget subtree that drops a binary
  # path into /tmp within 30s. We curl localhost so the network call
  # never leaves the host — works even on a fully air-gapped VM. The rule
  # only inspects the EXEC chain (osascript → curl → /tmp/stage2 path
  # appearing as a downstream exec), not whether the HTTP request
  # succeeded.
  local stage2="$WORKDIR/synthetic_stage2"
  /usr/bin/osascript -e "do shell script \"/usr/bin/curl -m 2 -o $stage2 http://127.0.0.1:9/edr-runbook-synthetic 2>/dev/null; chmod +x $stage2 2>/dev/null; $stage2 2>/dev/null\"" 2>/dev/null || true
  EXPECTED_ALERTS+=("osascript_network_exec — osascript → curl → $stage2")
}

step_credential_keychain_dump() {
  hr
  echo "[runbook] credential_keychain_dump — security dump-keychain"
  # Rule trigger: exec of /usr/bin/security with "dump-keychain" as the
  # first non-flag argv token. Run with stdin redirected from /dev/null so
  # the binary fails immediately on the password prompt rather than
  # hanging. Rule fires on exec regardless of dump success.
  /usr/bin/security dump-keychain </dev/null >/dev/null 2>&1 || true
  EXPECTED_ALERTS+=("credential_keychain_dump — /usr/bin/security dump-keychain")
}

step_privilege_launchd_plist_write() {
  hr
  echo "[runbook] privilege_launchd_plist_write — non-platform writer drops a daemon plist"
  # Rule trigger: write-mode open() to /Library/LaunchDaemons/<name>.plist
  # by a process whose code-signing is_platform_binary=false AND whose
  # team_id is not in EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST. cp / dd / tee /
  # /bin/bash are all platform binaries and DO NOT fire the rule. We
  # build a tiny Go writer in the runbook's working dir; an unsigned local
  # binary is the closest stand-in for "an attacker dropper" without
  # smuggling actual malware.
  if ! command -v go >/dev/null 2>&1; then
    echo "[runbook] go not installed — skipping privilege_launchd_plist_write step"
    EXPECTED_ALERTS+=("privilege_launchd_plist_write — SKIPPED (no Go toolchain on this host)")
    return
  fi
  local src="$WORKDIR/synthetic_dropper.go"
  local bin="$WORKDIR/synthetic_dropper"
  cat > "$src" <<'GO'
package main

// Synthetic dropper for the EDR runbook. Writes a placeholder plist into
// /Library/LaunchDaemons/ to exercise the privilege_launchd_plist_write
// rule, then removes the file. Compiled locally so it lacks Apple's
// platform-binary flag — that's the bit the rule actually keys on.
import (
	"log"
	"os"
)

func main() {
	const target = "/Library/LaunchDaemons/com.synthetic.edr-runbook.plist"
	const body = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>com.synthetic.edr-runbook</string>
</dict></plist>
`
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		log.Fatalf("write: %v", err)
	}
	if err := os.Remove(target); err != nil {
		log.Printf("cleanup remove: %v", err)
	}
}
GO
  if ! go build -o "$bin" "$src"; then
    echo "[runbook] go build failed — skipping step"
    EXPECTED_ALERTS+=("privilege_launchd_plist_write — SKIPPED (go build failed)")
    return
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "[runbook] this step needs root to write into /Library/LaunchDaemons; re-running with sudo"
    sudo "$bin" || echo "[runbook] sudo dropper failed — alert may not have fired"
  else
    "$bin" || echo "[runbook] dropper failed — alert may not have fired"
  fi
  EXPECTED_ALERTS+=("privilege_launchd_plist_write — synthetic-dropper wrote /Library/LaunchDaemons/com.synthetic.edr-runbook.plist")
}

step_shell_from_office_note() {
  hr
  echo "[runbook] shell_from_office — NOT exercised by this script"
  # The rule keys on /Applications/Microsoft <App>.app/Contents/MacOS/<App>
  # as the parent process, with /bin/{sh,bash,zsh} as the child within 30s.
  # Office isn't installed on the dev VM. The plan calls out spoofing this
  # chain via the Swift test harness; that's tracked separately. Listed
  # here so the runbook output makes the deliberate omission explicit
  # rather than silently leaving operators wondering.
  EXPECTED_ALERTS+=("shell_from_office — INTENTIONALLY NOT exercised (no Office on the VM)")
}

main() {
  echo "[runbook] Fleet EDR Phase-7 synthetic attacker — $(date -u)"
  echo "[runbook] working dir: $WORKDIR"
  step_suspicious_exec
  step_persistence_launchagent
  step_dyld_insert
  step_osascript_network_exec
  step_credential_keychain_dump
  step_privilege_launchd_plist_write
  step_shell_from_office_note
  hr
  echo "[runbook] Done. Expected alerts in the admin UI:"
  for a in "${EXPECTED_ALERTS[@]}"; do
    echo "  - $a"
  done
  hr
  echo "[runbook] Verify in the admin UI:"
  echo "    open 'http://<server>:8088/ui/alerts'"
  echo "[runbook] Cleanup: rm -rf $WORKDIR (/Library/LaunchDaemons drop is removed by the dropper itself)"
}

main "$@"
