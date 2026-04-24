# Manual agent install (no MDM)

Use this path to:

- Evaluate Fleet EDR on one to five Macs.
- Install on a dev machine that isn't MDM-enrolled.
- Reproduce a customer's install-time issue without their full MDM.

For production deployments of more than a handful of Macs, use
[mdm-deployment.md](mdm-deployment.md) instead. The manual path requires
a human to click through the sysext approval and the Full Disk Access
grant, which doesn't scale.

## Prerequisites

- macOS 13 (Ventura) or later, Apple Silicon only.
- Admin (sudo) on the Mac.
- A reachable Fleet EDR server. You need its URL and the `enroll_secret`
  from the server's `./secrets/enroll_secret`.
- Optionally, the SHA-256 fingerprint of the server's TLS cert, for
  pinned installs. Otherwise the agent validates against the system
  trust store.

## Step 1: download the pkg

Pick a release from https://github.com/getvictor/fleet-edr/releases and
download the `.pkg` to the target Mac. Example for v0.1.0:

```sh
cd ~/Downloads
curl -fLO https://github.com/getvictor/fleet-edr/releases/download/v0.1.0/fleet-edr-v0.1.0.pkg
```

Verify the download against the published SHA256SUMS:

```sh
curl -fLO https://github.com/getvictor/fleet-edr/releases/download/v0.1.0/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Expect: `fleet-edr-v0.1.0.pkg: OK`.

## Step 2: verify the signature

Before you run an installer you didn't build, confirm Gatekeeper trusts
it. These checks pass without any developer tools installed; they use
binaries shipped in the base macOS image.

```sh
# Signed by us + notarized by Apple
pkgutil --check-signature fleet-edr-v0.1.0.pkg
# Expect:
#   Status: signed by a developer certificate issued by Apple for distribution
#   Notarization: trusted by the Apple notary service

# Stapled ticket embedded (works offline)
xcrun stapler validate fleet-edr-v0.1.0.pkg
# Expect: "The validate action worked!"

# Gatekeeper's install assessment
spctl -a -v --type install fleet-edr-v0.1.0.pkg
# Expect: "accepted / source=Notarized Developer ID"
```

If any of these fail, STOP. Don't install. File an issue at
https://github.com/getvictor/fleet-edr/issues.

## Step 3: write the config file

The agent reads `/etc/fleet-edr.conf` on every start. Without that file,
the daemon logs "EDR_SERVER_URL is not set" and exits. Create it BEFORE
running the installer so the daemon enrolls on its first boot:

```sh
sudo tee /etc/fleet-edr.conf >/dev/null <<'EOF'
EDR_SERVER_URL=https://edr.example.com
EDR_ENROLL_SECRET=paste-the-enroll-secret-here
# Optional: pin the server's TLS cert by SHA-256 fingerprint. Leave blank
# to validate against the system trust store. Use this when the server
# uses a self-signed cert (lab / air-gapped pilot).
# EDR_SERVER_FINGERPRINT=sha256//abc...
EOF
sudo chmod 0644 /etc/fleet-edr.conf
```

Replace `https://edr.example.com` with your server URL and
`paste-the-enroll-secret-here` with the value from the server's
`./secrets/enroll_secret` file.

## Step 4: install the pkg

```sh
sudo installer -pkg ~/Downloads/fleet-edr-v0.1.0.pkg -target /
```

Expect:

```
installer: Package name is Fleet EDR
installer: Installing at base path /
installer: The install was successful.
```

What the installer laid down:

| Path | Purpose |
|---|---|
| `/usr/local/bin/fleet-edr-agent` | agent daemon binary (Go, hardened runtime) |
| `/Applications/Fleet EDR.app` | host app containing the embedded sysext |
| `/Library/LaunchDaemons/com.fleetdm.edr.agent.plist` | LaunchDaemon config |
| `/Library/Application Support/com.fleetdm.edr/uninstall.sh` | uninstaller |
| `/Library/Application Support/com.fleetdm.edr/VERSION` | installed version string |
| `/var/db/fleet-edr/` | queue database + enrolled token (created post-install) |
| `/var/log/fleet-edr-agent.log` | agent stdout/stderr |

The postinstall script loads the LaunchDaemon. The agent starts
immediately, reads `/etc/fleet-edr.conf`, enrolls with the server, and
begins polling for commands.

## Step 5: approve the system extension

The installer only stages the sysext; activating it requires a human
click on a Mac that isn't MDM-managed. macOS shows a "System Extension
Blocked" notification the first time the host app tries to activate it.

1. Open **System Settings > Privacy & Security**.
2. Scroll to "Security". You'll see
   *"System extension blocked. Click to allow"* or a similar message.
3. Click **Allow**. Authenticate with your user password.
4. The sysext enters `activated waiting for user` → `activated enabled`.

Verify:

```sh
systemextensionsctl list
# Expect a row showing:
#   * * FDG8Q7N4CC com.fleetdm.edr.securityextension (x.y.z) Fleet EDR Security Extension [activated enabled]
```

Until the sysext is activated, the agent runs but sees no ES events. The
agent log repeats `receiver reconnecting ...` while it waits for the
sysext's XPC service to come up. That's expected.

## Step 6: grant Full Disk Access

The sysext's Endpoint Security client requires Full Disk Access to
observe file events. Without it, `es_new_client` returns
`ERR_NOT_PERMITTED` and no events flow.

1. Open **System Settings > Privacy & Security > Full Disk Access**.
2. Click the `+` button. Authenticate.
3. Navigate to `/Applications/Fleet EDR.app` and add it.
4. Also add `/usr/local/bin/fleet-edr-agent` (use
   Cmd+Shift+G in the file picker to type the path directly).
5. Toggle both entries ON.

## Step 7: verify end-to-end

The agent should be enrolled and posting events to the server.

On the Mac:

```sh
# Daemon is running
sudo launchctl print system/com.fleetdm.edr.agent | grep state
# Expect: "state = running"

# Recent log
sudo tail -n 20 /var/log/fleet-edr-agent.log
# Expect an "agent enrolled" line near the top, then periodic
# "http request" lines as the commander polls.
```

In the admin UI (https://edr.example.com/ui/):

1. Log in as `admin@fleet-edr.local` with the password captured at
   server boot.
2. Open the Hosts page. The new host appears with its hardware UUID,
   hostname, and a "last seen" timestamp that updates every ~5 seconds.
3. Run a process on the Mac (e.g., `ls -la`). It appears in the host's
   process tree within a few seconds.

## Upgrade

Download the newer `.pkg` and run `installer -pkg` again. The installer
detects the existing receipts and performs an upgrade:

```sh
sudo installer -pkg fleet-edr-v0.1.1.pkg -target /
```

The preinstall script stops the old daemon, the postinstall script
starts the new one. The persisted host token at
`/var/db/fleet-edr/enrolled.plist` survives, so the agent keeps its
existing enrollment — no re-approval needed.

## Uninstall

```sh
sudo /Library/Application\ Support/com.fleetdm.edr/uninstall.sh
```

The script tears down everything the pkg installed + deletes the runtime
state under `/var/db/fleet-edr` and `/var/log/fleet-edr-agent.log`. It
DELIBERATELY preserves `/etc/fleet-edr.conf` so a subsequent re-install
picks up the same enroll config. If you want a truly clean slate:

```sh
sudo rm /etc/fleet-edr.conf
```

After uninstall, the host disappears from the admin UI only after its
`last_seen` threshold (default 5 min) elapses. You can also revoke the
enrollment manually via `POST /api/v1/admin/enrollments/{host_id}/revoke`
(see [api.md](api.md)).

## Troubleshoot

**`installer: Error - Fleet EDR requires Apple Silicon (M1 or later).`**
You're on an Intel Mac. We don't ship Intel builds. Apple Silicon only.

**`installer: Error - Fleet EDR requires macOS 13 (Ventura) or later.`**
Upgrade macOS before installing.

**Installer runs but the daemon never starts. `launchctl print` says
"Could not find service".**
The postinstall script probably failed. Check
`sudo tail /var/log/install.log`. Common causes: `/Library/LaunchDaemons`
owned by the wrong user, or `launchctl bootstrap` hit a permission error.
Run:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.fleetdm.edr.agent.plist
sudo launchctl kickstart -k system/com.fleetdm.edr.agent
```

**Agent log shows `enrollment failed: unauthorized (401)`.**
The `EDR_ENROLL_SECRET` in `/etc/fleet-edr.conf` doesn't match what the
server has in `./secrets/enroll_secret`. Copy the exact value (no
trailing newline). Restart with
`sudo launchctl kickstart -k system/com.fleetdm.edr.agent`.

**Agent log shows `tls: failed to verify certificate: x509: ...`.**
Server's TLS cert isn't trusted by the system. Either install the CA
that signed it into the system trust store, or use the
`EDR_SERVER_FINGERPRINT` pin (computed via
`openssl x509 -in fullchain.pem -noout -fingerprint -sha256`, formatted
as `sha256//<base64>`). Don't set `EDR_ALLOW_INSECURE=1` unless you're
in a lab.

**System extension stays in `activated waiting for user` forever.**
Someone disabled Automation + extensions in the OS. Easiest fix: revoke
the install, reinstall with the MDM path (which pushes the
sysext-allow-list profile so the prompt doesn't appear).

**Full Disk Access grant gets wiped after every reboot.**
Probably a TCC-database issue after a macOS point upgrade. Re-add the
entries in Privacy & Security. If it recurs on a managed Mac, deploy
the TCC profile via MDM instead.
