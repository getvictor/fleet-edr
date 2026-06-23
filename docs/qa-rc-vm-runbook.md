# RC validation runbook (live edr-qa + dev server)

How to execute the agent/extension RC gate (the [QA: v0.3.0 RC validation](https://github.com/getvictor/fleet-edr/issues/450) style checklist) against the real `edr-qa` VM and a local dev server, including the headless techniques that let it run from an SSH-only / remote dev environment with no GUI access to the VM. This is the hands-on companion to the System / VM (L5) layer in [testing-strategy.md](testing-strategy.md).

Use this when an RC is cut and you need to exercise ESF, XPC, the event wire format, and app control end to end on a SIP-on, Gatekeeper-on host. None of the steps below require code changes; they drive the shipped binaries plus the server API.

## Topology

- `edr-qa`: the release-validation VM (SIP on, Gatekeeper on, no MDM). Reaches the workstation over the bridge at `192.168.64.1`. SSH via the keyed login; `sudo` needs a password over the keyed session, so pipe it with `sudo -S`.
- Dev server: run the RC server code locally so the box under test talks to a known build. Either check out the RC tag and `go run`, or run the published `ghcr.io/getvictor/fleet-edr-server:<tag>` image. It binds `0.0.0.0:8088` so the VM can reach it at `192.168.64.1:8088`.
- Observability: the agent and server export OTel; route both to the MCP-visible SigNoz tagged `deployment.environment=dev-local` and filter on that so dev signals do not mix with prod.

## 1. Bring up the dev server on the RC code

Check out the RC tag so the server (and its embedded UI) match what is shipping. The working tree returns to detached HEAD; the contributor's branch is untouched.

```sh
git checkout vX.Y.Z-rc.N          # the RC under validation, e.g. v0.3.0-rc.2
(cd ui && npm run build)         # server/ui/dist is gitignored, so rebuild for the RC UI
```

Launch the server directly (not `task dev:server`, whose Taskfile env pins OTel to a local collector). Pulling the `OTEL_*` exports from the shell profile points telemetry at the remote SigNoz with the `dev-local` tag:

```sh
eval "$(grep '^export OTEL_' ~/.zshrc 2>/dev/null)"   # remote OTLP endpoint + bearer token + deployment.environment=dev-local
export EDR_DSN='root:@tcp(127.0.0.1:33306)/edr?parseTime=true'
export EDR_ENROLL_SECRET=dev-enroll-secret
export EDR_TLS_CERT_FILE=tmp/dev.crt EDR_TLS_KEY_FILE=tmp/dev.key
export EDR_LISTEN_ADDR=0.0.0.0:8088 EDR_UI_LIVE_DIR=server/ui/dist
export EDR_SECRET_KEY=dev-only-secret-key-do-not-use-in-production-xyz
export EDR_AUTH_ALLOW_NO_OIDC=1 EDR_BREAKGLASS_RP_ID=localhost EDR_BREAKGLASS_RP_ORIGINS=https://localhost:8088
export OTEL_SERVICE_NAME=fleet-edr-server
unset OTEL_EXPORTER_OTLP_INSECURE
go run ./server/cmd/fleet-edr-server
```

If a stale dev server already holds `:8088`, the new one fails with `bind: address already in use` and the old build keeps serving. Kill the stale `go run` and its compiled child first (`lsof -nP -iTCP:8088 -sTCP:LISTEN`).

## 2. Point edr-qa at the dev server

The dev TLS cert (mkcert) only covers `localhost`, but the agent's fingerprint pin sets `InsecureSkipVerify` and does its own SHA-256 equality check, so pinning bypasses the hostname mismatch. Compute the pin from `tmp/dev.crt`:

```sh
# Extract just the hex (':' separators are fine; the parser accepts those and an optional
# 'sha256:' prefix). Do NOT paste the raw output: openssl prefixes it with "SHA256 Fingerprint="
# which the parser does not strip, so the pin would fail to decode.
PIN=$(openssl x509 -in tmp/dev.crt -noout -fingerprint -sha256 | cut -d= -f2)
```

The agent binds its enrolled token to the exact `server_url`, so changing the URL invalidates the token. Write the conf, delete the token to force a fresh enroll, and restart. `PW` is the edr-qa sudo password: set it once with `read -rs PW`, or drop the `echo "$PW" |` prefix and let `sudo` prompt. Avoid a heredoc that collides with `sudo -S` stdin; stage the file then copy it:

```sh
printf 'EDR_SERVER_URL=https://192.168.64.1:8088\nEDR_ENROLL_SECRET=dev-enroll-secret\nEDR_SERVER_FINGERPRINT=%s\n' "$PIN" > /tmp/fe.conf   # $PIN from the previous block (same shell)
echo "$PW" | sudo -S cp /tmp/fe.conf /etc/fleet-edr.conf
echo "$PW" | sudo -S rm -f /var/db/fleet-edr/enrolled.plist
echo "$PW" | sudo -S launchctl kickstart -k system/com.fleetdm.edr.agent
```

Confirm `agent enrolled` plus `receiver connected` for both the Endpoint Security and Network Extension services in `/var/log/fleet-edr-agent.log`, then confirm exec/fork/network/dns rows land in the dev DB (`docker exec fleet-edr-mysql mysql -uroot -e "SELECT event_type, COUNT(*) FROM edr.events WHERE host_id LIKE '<uuid-prefix>%' AND created_at > (NOW() - INTERVAL 2 MINUTE) GROUP BY event_type;"`).

## 3. Forge an admin session for the API and UI

Dev auth is break-glass WebAuthn, which a script cannot complete, so mint a session row directly against the seeded super_admin. Look the user id up by email (the seed auto-increments it via `CreateBreakglass`, so it is not guaranteed to be 1). The cookie carries a random token; the stored `sessions.id` is its SHA-256; `csrf_token` is stored raw and the `X-Csrf-Token` header is its base64url form. The seeded role lives in `role_bindings`, not a column on `users`.

```python
import os, hashlib, base64
tok, csrf = os.urandom(32), os.urandom(32)
print("cookie:", base64.urlsafe_b64encode(tok).rstrip(b'=').decode())
print("id_hex:", hashlib.sha256(tok).hexdigest())
print("csrf_hex:", csrf.hex())
```

```sh
UID=$(docker exec fleet-edr-mysql mysql -uroot -N -e "SELECT id FROM edr.users WHERE email='admin@fleet-edr.local';")
# auth_method='oidc' lands the session in the normal 8h/24h timeout class. 'local_password' is the
# break-glass class (15-minute idle / 1-hour absolute) and would expire the session mid-spot-check.
docker exec fleet-edr-mysql mysql -uroot -e "INSERT INTO edr.sessions (id,user_id,identity_id,auth_method,csrf_token,created_at,last_seen_at,last_auth_at,expires_at) VALUES (UNHEX('<id_hex>'),$UID,NULL,'oidc',UNHEX('<csrf_hex>'),NOW(6),NOW(6),NOW(6),NOW(6)+INTERVAL 1 DAY);"
```

Send `Cookie: edr_session=<cookie>` on every call, and `X-Csrf-Token` (read the live value from `GET /api/session`) on every unsafe method. The session is good for the dashboard too, but the cookie is `HttpOnly`, so a browser cannot be seeded by JavaScript; verify feature backends over the API instead and rely on vitest/Playwright for component rendering.

## 4. Activate a freshly-upgraded system extension headlessly (no GUI login)

This is the step that unblocks a remote run. An in-place pkg upgrade installs the new bundle but does not stage it: the host app must submit the `OSSystemExtensionRequest`, and macOS only accepts that from a logged-in user session. With a console user present, kick the activation agent in its GUI domain:

```sh
UID_C=$(stat -f %u /dev/console)
sudo launchctl kickstart -k "gui/$UID_C/com.fleetdm.edr.activate"
```

With NO console user (the usual headless state, console uid 0, no `gui/<uid>` domain), the `user/<uid>` launchd domain still exists. Run the host app's `activate` subcommand in that user context. It uses `dispatchMain()`, not AppKit, so it needs no Aqua session:

```sh
U=<login-user>   # the VM's GUI/login user (e.g. victor); asuser needs its uid, computed below
sudo launchctl asuser "$(id -u "$U")" sudo -u "$U" "/Applications/Fleet EDR.app/Contents/MacOS/edr" activate &
```

A same-team version bump auto-approves (no Allow click). The request succeeds from that `user/<uid>` context; `systemextensionsctl list` then shows the new version `activated enabled` and the old one `terminated waiting to uninstall on reboot`. The `activate` subcommand also re-enables the content filter and DNS proxy, so the new Network Extension takes over its Mach service immediately and telemetry stays continuous (no stranding). The SSH session may briefly drop while the filter re-enables; reconnect, the box is fine. Reboot to finish the cutover (old version uninstalls); the activated extension comes back enabled headless.

## 5. App-control exec enforcement needs a notarized binary

On a SIP-on, Gatekeeper-on host, AMFI SIGKILLs any non-platform binary you create locally: a copied platform binary and an ad-hoc re-signed copy both die at exec (exit 137, a code-signing crash report of type 309 under `/Library/Logs/DiagnosticReports`) before app control ever decides. Platform binaries (`/bin/echo` direct) run but are unconditionally allowed by the extension, so a rule cannot block them. So exit 137 on a `/tmp` test binary is a code-signing kill, not an app-control DENY.

The fix is a real notarized Developer ID binary: valid signature so AMFI runs it, non-Apple so it is non-platform and the extension decides. GitHub's `gh` CLI works well, and downloading with `curl` adds no quarantine xattr, so there is no Gatekeeper prompt:

```sh
URL=$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest | grep -o 'https://[^"]*macOS_arm64.zip' | head -1)
curl -fsSL -o gh.zip "$URL" && unzip -oq gh.zip
cp gh_*/bin/gh /tmp/qa-gh && /tmp/qa-gh --version    # runs (exit 0)
shasum -a 256 /tmp/qa-gh ; codesign -dvvv /tmp/qa-gh 2>&1 | grep CDHash=
```

Tell an app-control DENY apart from an AMFI kill by the extension log line `AUTH_EXEC DENIED` (subsystem `com.fleetdm.edr.securityextension`) with no crash report. Push a block rule by cdhash to the per-policy route (the bare `/api/v1/app-control/rules` is GET only; create lives under the policy, and DELETE wants its `reason` in a JSON body, not a query param):

```sh
curl -sk -X POST https://localhost:8088/api/v1/app-control/policies/1/rules -H "Cookie: edr_session=..." -H "X-Csrf-Token: ..." \
  --data '{"rule_type":"CDHASH","identifier":"<cdhash>","reason":"RC QA"}'
```

Adding a rule bumps the policy version and fans out a `set_application_control` command. Watch `commander set_application_control ... policy_version=N` in the agent log and `applied app control snapshot: ... version=N ... rules=K` in the extension log to confirm propagation.

### #209 kernel-cached ALLOW + es_clear_cache

Exec the notarized binary a few times so the decided ALLOW is pinned into the kernel cache, then push a cdhash block. The next exec must be DENIED: that proves `es_clear_cache` fired on the snapshot swap so the cached ALLOW did not outlive the rule. Delete the rule and confirm it runs again. The cache-hit count itself (handler entered far fewer times than execs) is not observable at a persisted log level because a decided ALLOW is silent; it is covered by the `authResultIsCacheable` unit tests.

### #402 / #322 re-sync after a policy-version regression

Simulate a server DB restore: force the version down, then add a rule so the next mutation stamps a newer `updated_at` epoch.

```sh
docker exec fleet-edr-mysql mysql -uroot -e "UPDATE edr.app_control_policies SET version=50 WHERE id=1;"
# then POST a block rule -> version becomes 51 (below the extension's active version) with a new epoch
```

The extension logs `version regressed (X -> Y) but epoch advanced ...; re-syncing (likely server DB restore)` and applies the regressed snapshot, so the new block takes effect rather than freezing on the stale higher version. Restore the version counter afterward.

## 6. Edge-rejection resilience (#398)

The agent must keep telemetry queued on a blanket edge rejection (a 4xx the server never emits itself) rather than quarantining it. Front the dev server with a small toggleable TLS reverse proxy that reuses `tmp/dev.crt` (so the existing fingerprint pin still matches) and returns 403 only on `POST /api/events` while forwarding enroll and commands. Point the agent at the proxy (this needs a fresh enroll, since the token is bound to the URL), then:

- Sustain 403 well past the old 10-tick threshold: expect repeated `uploader endpoint rejecting uploads; batch kept queued` with zero quarantine drops, and `edr.agent.uploader.endpoint_rejected` climbing.
- Restore 200: the backlog drains.
- Return a genuine 400 (poison batch): that still quarantines.

The agent only exports its own metrics if `OTEL_*` is set in its LaunchDaemon plist; do not write a real bearer token onto the VM just for this. The agent log lines above are sufficient evidence; the counter is unit-tested.

## 7. Server-side checks via synthetic ingest

For wire-format and ingest behavior that does not depend on a specific extension build, enroll a synthetic host and POST crafted events (plain JSON, no gzip, `Authorization: Bearer <host_token>` from `POST /api/enroll`; `hardware_uuid` must be a real UUID). Examples:

- #408 heartbeat drop: send a batch with an exec plus a `snapshot_heartbeat`; the heartbeat is accepted but not persisted as a row, `edr.ingest.heartbeats_dropped` climbs, and a snapshot exec (`"snapshot": true`) seeds `last_seen_ns`.
- #403 / #425 / #414: send exec and network_connect carrying `pidversion`; confirm the process row stores `pidversion` and the flow resolves to the process by pid plus pidversion.

Clean up the synthetic host rows when done.

## 8. Observability

Validate any OTel-affecting change through the SigNoz MCP, not screenshots. Dev signals share the prod backend, so always filter `deployment.environment = 'dev-local'`. The dev server's traces (for example the detection monitor-mode signal) and counters land there; the agent's own metrics only appear if its plist exports `OTEL_*`.

## 9. Cleanup

- Remove any app-control rules created during the run and restore the policy version counter.
- Delete synthetic hosts and downloaded test binaries from the VM.
- Stop the dev server and any edge proxy; return the working tree to the contributor's branch.
- Reboot edr-qa (or revert its snapshot) so the next run starts from a known-good state.

## What needs a console GUI login

A truly fresh install (no prior approved version) still needs a human to approve the extension and grant Full Disk Access in System Settings, which SSH cannot do. The headless `asuser` activation in section 4 only covers upgrading an already-approved, same-team extension. For a clean-slate install on a no-MDM box, use a console session or the MDM profile path.
