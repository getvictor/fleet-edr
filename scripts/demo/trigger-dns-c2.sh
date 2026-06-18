#!/usr/bin/env bash
# Trigger the dns_c2_beacon detection on a live Fleet EDR agent.
#
# Run this ON the enrolled Mac (the host whose agent + system/network extensions are active). It simulates the classic
# "malware phones home" chain so the EDR can correlate three separate telemetry streams into ONE alert:
#   exec (Endpoint Security) + dns_query (DNS proxy) + network_connect (network filter).
#
# Detection target: catalog rule dns_c2_beacon (server/rules/internal/catalog/dns_c2_beacon.go).
# Synthetic equivalent: test/efficacy/corpus/T1071.004-dns-c2-beacon (fakeagent, no live host).
#
# Prerequisites: an Apple Silicon Mac on macOS 13+ with the agent installed, the system + network extensions active, and
# Full Disk Access granted. The host must reach the internet: the beacon resolves a nip.io name (plain UDP DNS, which the
# proxy sees) and opens a real outbound TCP connection to the resolved address.
#
# Usage: ./trigger-dns-c2.sh [critical|high]
#   critical (default): high-entropy DGA-like domain -> Critical, ATT&CK T1071.004 + T1568.002.
#   high:               ordinary short domain        -> High,     ATT&CK T1071.004.
set -euo pipefail

MODE="${1:-critical}"
case "$MODE" in
  critical|high) ;;
  *) echo "usage: $0 [critical|high]" >&2; exit 2 ;;
esac

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }   # cyan step banner
sub() { printf '    %s\n' "$1"; }                       # indented detail

# Stage the payload at a fixed temp path and guarantee it is removed on ANY exit. Step 4 narrates the cleanup as part of
# the demo; this trap covers the early-failure paths (e.g. the exec check below) so a failed run never leaves an
# executable copy of curl behind in /tmp. rm -f is idempotent, so the trap and the Step 4 narrative do not conflict.
BEACON=/tmp/beacon
cleanup() { rm -f "$BEACON"; }
trap cleanup EXIT

say "DNS C2 beacon demo  (mode: ${MODE})"
sub "Simulating the classic 'malware phones home' chain on this host."
sub "Fleet EDR should correlate three separate signals into ONE alert:"
sub "  exec (Endpoint Security) + dns_query (DNS proxy) + network_connect (network filter)."

# --- Step 1: stage the payload in a suspicious location -----------------------------
say "Step 1/4  Drop the payload into a world-writable temp directory"
cp /usr/bin/curl "$BEACON"
# /usr/bin/curl is an Apple *platform binary*. A plain copy executed from /tmp is SIGKILLed by AMFI on
# macOS (the process dies with exit 137 = 128+9 before it can resolve or connect), so no dns_query or
# network_connect telemetry is ever emitted and the rule has nothing to join. Re-signing ad-hoc strips
# the platform-binary designation and applies a valid signature, so the copy runs from /tmp.
codesign --force --sign - "$BEACON" >/dev/null 2>&1
sub "Copied a network client to ${BEACON} (re-signed ad-hoc so macOS will run it from /tmp)"
# Fail loudly if the staged payload still cannot execute, rather than silently emitting no telemetry.
if ! "$BEACON" --version >/dev/null 2>&1; then
  echo "ERROR: ${BEACON} cannot execute (SIGKILLed by macOS code-signing enforcement)." >&2
  echo "       Without a running payload no dns_query/network_connect is emitted, so no alert can fire." >&2
  exit 1
fi
sub "Why it matters: the rule's isSuspiciousPath() gate only considers processes launched"
sub "from /tmp, /var/tmp, /private/tmp, or /dev/shm. A browser resolving+connecting never fires;"
sub "a binary running out of /tmp does. This is the 'dropped payload' shape."

# --- Step 2: choose the command-and-control domain ----------------------------------
say "Step 2/4  Pick the command-and-control (C2) domain"
SINK_IP=1.1.1.1   # any routable IP; the outbound TCP SYN alone emits network_connect
if [ "$MODE" = "critical" ]; then
  # high-entropy 18-char label -> looksLikeDGADomain() -> Critical + ATT&CK T1568.002.
  # Read a finite chunk of /dev/urandom and slice in bash; piping urandom into `head -c`
  # closes the pipe early and kills `tr` with SIGPIPE (exit 141) under `set -o pipefail`.
  rand=$(head -c 1024 /dev/urandom | LC_ALL=C tr -dc '[:lower:][:digit:]')
  LABEL=${rand:0:18}
  sub "Generated a high-entropy, algorithm-looking hostname (a DGA domain)."
  sub "Why it matters: a long random label trips the entropy check, escalating the"
  sub "finding to CRITICAL and adding ATT&CK T1568.002 (Domain Generation Algorithms)."
else
  # short label (<12 chars) -> no DGA -> stays High; random to dodge DNS cache.
  rand=$(head -c 256 /dev/urandom | LC_ALL=C tr -dc '[:lower:]')
  LABEL="app-${rand:0:5}"
  sub "Using a short, ordinary-looking hostname (no DGA)."
  sub "Why it matters: the finding stays HIGH with ATT&CK T1071.004 (DNS) only."
fi
DOMAIN="${LABEL}.${SINK_IP}.nip.io"
sub "C2 domain: ${DOMAIN}"
sub "(nip.io resolves <label>.<ip>.nip.io to <ip>, so the lookup returns ${SINK_IP},"
sub " which is exactly where the payload will connect: a self-contained beacon.)"

# --- Step 3: resolve then connect, from the same process ----------------------------
say "Step 3/4  Beacon home: resolve the domain, then connect to the resolved address"
sub "Running: ${BEACON} https://${DOMAIN}/"
sub "Why it matters: the SAME /tmp process does the DNS lookup (-> DNS proxy emits dns_query"
sub "with the resolved address) and then the outbound connection to that address (-> network"
sub "filter emits network_connect). Resolve-then-connect, same PID, inside the 30s window."
# -4 forces IPv4 so the connected address equals the captured A-record answer (${SINK_IP}); without it
# curl may use an AAAA result and the connect IP won't match the dns_query response_addresses the rule joins on.
"$BEACON" -4 -s -m 5 -o /dev/null "https://${DOMAIN}/" || true   # connect is enough; app-layer result irrelevant
sub "Beacon sent (the TLS/HTTP result does not matter; the connection attempt is the signal)."

# --- Step 4: clean up and hand off to the EDR ---------------------------------------
say "Step 4/4  Clean up"
rm -f "$BEACON"
sub "Removed ${BEACON} (typical of malware covering its tracks)."

say "Done. Now watch Fleet EDR."
sub "Within a few seconds an alert should appear in the EDR UI:"
sub "  Title:    DNS C2 beacon"
if [ "$MODE" = "critical" ]; then
  sub "  Severity: Critical   ATT&CK: T1071.004 + T1568.002"
else
  sub "  Severity: High       ATT&CK: T1071.004"
fi
sub "  Detail:   /tmp/beacon resolved ${DOMAIN} and connected to ${SINK_IP}"
sub "The single finding cites the dns_query and the network_connect, attributed to the"
sub "/tmp/beacon process: launch -> lookup -> connection joined across all three streams."
