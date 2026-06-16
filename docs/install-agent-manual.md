# Manual agent install (no MDM)

Use this path to:

- Evaluate Fleet EDR on one to five Macs.
- Install on a dev machine that isn't MDM-enrolled.
- Reproduce a customer's install-time issue without their full MDM.

For production deployments of more than a handful of Macs, use [mdm-deployment.md](mdm-deployment.md) instead. The manual path requires a human to click through the sysext approval and the Full Disk Access grant, which doesn't scale.

## Prerequisites

- macOS 13 (Ventura) or later, Apple Silicon only.
- Admin (sudo) on the Mac.
- A reachable Fleet EDR server. You need its URL and the `enroll_secret` from the server's `./secrets/enroll_secret`.
- Optionally, the SHA-256 fingerprint of the server's TLS cert, for pinned installs. Otherwise the agent validates against the system trust store.

## Step 1: download the pkg

Pick a release from https://github.com/getvictor/fleet-edr/releases and download the `.pkg` to the target Mac. Example for v0.2.0:

```sh
cd ~/Downloads
curl -fLO https://github.com/getvictor/fleet-edr/releases/download/v0.2.0/fleet-edr-v0.2.0.pkg
```

Verify the download against the published SHA256SUMS:

```sh
curl -fLO https://github.com/getvictor/fleet-edr/releases/download/v0.2.0/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Expect: `fleet-edr-v0.2.0.pkg: OK`.

## Step 2: verify the signature

Before you run an installer you didn't build, confirm Gatekeeper trusts it. These checks need no developer tools; they use binaries in the base macOS image.

```sh
# Signed by us + notarized by Apple
pkgutil --check-signature fleet-edr-v0.2.0.pkg
# Expect:
#   Status: signed by a developer certificate issued by Apple for distribution
#   Notarization: trusted by the Apple notary service

# Stapled ticket embedded (works offline)
xcrun stapler validate fleet-edr-v0.2.0.pkg
# Expect: "The validate action worked!"

# Gatekeeper's install assessment
spctl -a -v --type install fleet-edr-v0.2.0.pkg
# Expect: "accepted / source=Notarized Developer ID"
```

If any of these fail, STOP. Don't install. File an issue at https://github.com/getvictor/fleet-edr/issues.

### Optional: verify the Sigstore signature

Releases publish a single Sigstore bundle (`<file>.sigstore.json`) next to every artifact. The bundle carries the signature, the ephemeral signing certificate, and the transparency-log proof in one file, and ties the artifact to the exact GitHub Actions workflow run that produced it, which catches the rare attack where a Developer ID cert is stolen but the attacker can't push to our GitHub repo. Skip this step if you don't have `cosign` installed; the Apple-signature checks above are sufficient for most pilots.

Use the same release tag you downloaded in Step 1 in place of the `v0.2.0` placeholder below; the bundle and the `.pkg` must come from the same release.

```sh
# Install cosign (v3+) if you don't have it: brew install cosign
curl -fLO https://github.com/getvictor/fleet-edr/releases/download/v0.2.0/fleet-edr-v0.2.0.pkg.sigstore.json

cosign verify-blob \
    --bundle fleet-edr-v0.2.0.pkg.sigstore.json \
    --certificate-identity-regexp '^https://github\.com/getvictor/fleet-edr/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    fleet-edr-v0.2.0.pkg
# Expect: "Verified OK"
```

The same `<file>.sigstore.json` bundle covers `SHA256SUMS` and both `.mobileconfig` profiles. To verify the server image instead, pass the same keyless identity and issuer constraints:

```sh
cosign verify ghcr.io/getvictor/fleet-edr-server:v0.2.0 \
    --certificate-identity-regexp '^https://github\.com/getvictor/fleet-edr/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## Step 3: write the config file

The agent reads `/etc/fleet-edr.conf` on every start. Without that file, the daemon logs "EDR_SERVER_URL is not set" and exits. Create it BEFORE running the installer so the daemon enrolls on its first boot:

```sh
sudo tee /etc/fleet-edr.conf >/dev/null <<'EOF'
EDR_SERVER_URL=https://edr.example.com
EDR_ENROLL_SECRET=paste-the-enroll-secret-here
# Optional: pin the server's TLS cert by SHA-256 fingerprint. Leave blank
# to validate against the system trust store. Use this when the server
# uses a self-signed cert (lab / air-gapped pilot). Accepts the output
# of `openssl x509 -noout -fingerprint -sha256` (hex, optionally with
# `sha256:` prefix and/or `:` separators).
# EDR_SERVER_FINGERPRINT=sha256:AA:BB:CC:DD:EE:FF:...
EOF
sudo chmod 0600 /etc/fleet-edr.conf
```

Replace `https://edr.example.com` with your server URL and `paste-the-enroll-secret-here` with the value from the server's `./secrets/enroll_secret` file or `EDR_ENROLL_SECRET` env var.

## Step 4: install the pkg

```sh
sudo installer -pkg ~/Downloads/fleet-edr-v0.2.0.pkg -target /
```

Expect:

```text
installer: Package name is Fleet EDR
installer: Installing at base path /
installer: The install was successful.
```

What the installer laid down:

| Path                                                        | Purpose                                                |
| ----------------------------------------------------------- | ------------------------------------------------------ |
| `/usr/local/bin/fleet-edr-agent`                            | agent daemon binary (Go, hardened runtime)             |
| `/Applications/Fleet EDR.app`                               | host app containing the embedded sysext                |
| `/Library/LaunchDaemons/com.fleetdm.edr.agent.plist`        | LaunchDaemon config                                    |
| `/Library/Application Support/com.fleetdm.edr/uninstall.sh` | uninstaller                                            |
| `/Library/Application Support/com.fleetdm.edr/VERSION`      | installed version string                               |
| `/var/db/fleet-edr/`                                        | queue database + enrolled token (created post-install) |
| `/var/log/fleet-edr-agent.log`                              | agent stdout/stderr                                    |

The postinstall script loads the LaunchDaemon. The agent starts immediately, reads `/etc/fleet-edr.conf`, enrolls with the server, and begins polling for commands.

## Step 5: approve the system extensions

Fleet EDR ships two system extensions: an Endpoint Security extension (`com.fleetdm.edr.securityextension`, process and file events) and a Network Extension (`com.fleetdm.edr.networkextension`, network and DNS events). The pkg's activation LaunchAgent (`com.fleetdm.edr.activate`) runs the host app's `activate` right after install (and again at every login), but on a Mac that isn't MDM-managed each extension needs a human to approve it. macOS posts a notification when the host app requests activation.

On macOS 15 (Sequoia) and later:

1. Open **System Settings > General > Login Items & Extensions**.
2. Under **Extensions**, open **Endpoint Security Extensions**, enable **Fleet EDR**, and authenticate with your user password.
3. Open **Network Extensions** and enable **Fleet EDR** the same way. macOS also prompts to allow it to filter network content; click **Allow**.

On macOS 13 and 14 (Ventura and Sonoma), the controls live under **System Settings > Privacy & Security > Security** instead: click **Allow** on the _"System extension blocked"_ message for each extension and authenticate.

Each extension moves `activated waiting for user` → `activated enabled`.

Verify:

```sh
systemextensionsctl list | grep fleetdm
# Expect two rows, both ending [activated enabled]:
#   ... com.fleetdm.edr.securityextension ... [activated enabled]
#   ... com.fleetdm.edr.networkextension  ... [activated enabled]
```

Each extension feeds its own receiver loop, so until a given extension is activated the agent simply misses that extension's events; a partially-approved install is partial coverage, not a full outage. The agent logs a `receiver connect` warning per unavailable service, and the `service` field says which one: `FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc` is the Endpoint Security extension (process and file events), `group.com.fleetdm.edr.networkextension` is the Network Extension (network and DNS events). That's expected before activation. A warning for the Endpoint Security service that persists after activation is the Full Disk Access boot-loop in Step 6; a persistent Network Extension warning means that extension still needs approval in Step 5.

## Step 6: grant Full Disk Access

The Endpoint Security extension creates its ES client with `es_new_client`, which requires Full Disk Access. The extension is a separate TCC identity from the host app, so granting FDA to `/Applications/Fleet EDR.app` does NOT cover it. Without its own grant, `es_new_client` returns `ERR_NOT_PERMITTED`, the extension exits and relaunches in a loop, and the agent logs repeated `receiver connect` / `xpc_bridge_connect failed` warnings even though `systemextensionsctl` shows `activated enabled`.

1. Open **System Settings > Privacy & Security > Full Disk Access**.
2. After Step 5's activation the extension appears in the list as **"Fleet EDR Security Extension"** (its bundle display name). Toggle it ON and authenticate. This is the entry that lets `es_new_client` succeed.
3. Add the agent: click **+**, press Cmd+Shift+G, enter `/usr/local/bin/fleet-edr-agent`, and toggle it ON.
4. If no **"Fleet EDR Security Extension"** entry is listed, reset its TCC state and reboot to force a fresh prompt: `sudo tccutil reset SystemPolicyAllFiles com.fleetdm.edr.securityextension`.

Granting FDA mid-loop lets the next relaunch succeed within a few seconds; if the warnings don't clear, reboot. You don't need to grant FDA to the Network Extension ("Fleet EDR Network Extension") or to `/Applications/Fleet EDR.app`.

## Step 7: verify end-to-end

The agent should be enrolled and posting events to the server.

On the Mac:

```sh
# Daemon is running
sudo launchctl print system/com.fleetdm.edr.agent | grep state
# Expect: "state = running"

# Recent log
sudo tail -n 100 /var/log/fleet-edr-agent.log
# Expect an "agent enrolled" line near the top, then periodic
# "http request" lines as the commander polls.
```

In the admin UI (https://edr.example.com/ui/):

1. Log in as `admin@fleet-edr.local` with the password captured at server boot.
2. Open the Hosts page. The new host appears with its hardware UUID, hostname, and a "last seen" timestamp that updates every ~5 seconds.
3. Run a process on the Mac (e.g., `ls -la`). It appears in the host's process tree within a few seconds.

## Upgrade

Download the newer `.pkg` and run `installer -pkg` again. The installer detects the existing receipts and performs an upgrade:

```sh
sudo installer -pkg fleet-edr-v0.1.2.pkg -target /
```

The preinstall script stops the old daemon, the postinstall script starts the new one. The persisted host token at `/var/db/fleet-edr/enrolled.plist` survives, so the agent keeps its existing enrollment; no re-approval needed.

## Uninstall

```sh
sudo /Library/Application\ Support/com.fleetdm.edr/uninstall.sh
```

The script tears down everything the pkg installed + deletes the runtime state under `/var/db/fleet-edr` and `/var/log/fleet-edr-agent.log`. It DELIBERATELY preserves `/etc/fleet-edr.conf` so a subsequent re-install picks up the same enroll config. If you want a truly clean slate:

```sh
sudo rm /etc/fleet-edr.conf
```

After uninstall, the host disappears from the admin UI only after its `last_seen` threshold (default 5 min) elapses. You can also revoke the enrollment manually via `POST /api/enrollments/{host_id}/revoke` (see [api.md](api.md)).

## Troubleshoot

**`installer: Error - Fleet EDR requires Apple Silicon (M1 or later).`** You're on an Intel Mac. We don't ship Intel builds. Apple Silicon only.

**`installer: Error - Fleet EDR requires macOS 13 (Ventura) or later.`** Upgrade macOS before installing.

**Installer runs but the daemon never starts. `launchctl print` says "Could not find service".** The postinstall script probably failed. Check `sudo tail /var/log/install.log`. Common causes: `/Library/LaunchDaemons` owned by the wrong user, or `launchctl bootstrap` hit a permission error. Run:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.fleetdm.edr.agent.plist
sudo launchctl kickstart -k system/com.fleetdm.edr.agent
```

**Agent log shows `enrollment failed: unauthorized (401)`.** The `EDR_ENROLL_SECRET` in `/etc/fleet-edr.conf` doesn't match what the server has in `./secrets/enroll_secret`. Copy the exact value (no trailing newline). Restart with `sudo launchctl kickstart -k system/com.fleetdm.edr.agent`.

**Agent log shows `tls: failed to verify certificate: x509: ...`.** Server's TLS cert isn't trusted by the system. Either install the CA that signed it into the system trust store, or use the `EDR_SERVER_FINGERPRINT` pin. Compute the value with `openssl x509 -in fullchain.pem -noout -fingerprint -sha256` and paste the hex output into the config file (optionally with a `sha256:` prefix; the `:` separators between bytes are accepted too). Don't set `EDR_ALLOW_INSECURE=1` unless you're in a lab.

**System extension stays in `activated waiting for user` forever.** Someone disabled Automation + extensions in the OS. Easiest fix: revoke the install, reinstall with the MDM path (which pushes the sysext-allow-list profile so the prompt doesn't appear).

**`receiver connect` / `xpc_bridge_connect failed` warnings repeat while `systemextensionsctl list` shows `activated enabled`.** The Endpoint Security extension is exiting on launch for lack of Full Disk Access. Confirm with `log show --last 10m --predicate 'subsystem == "com.fleetdm.edr.securityextension"' | grep "ES client"`: `Failed to create ES client: 4` is `ERR_NOT_PERMITTED`. Enable the **"Fleet EDR Security Extension"** entry in Privacy & Security > Full Disk Access (Step 6). The extension is a different TCC identity from `/Applications/Fleet EDR.app`, so granting the app alone doesn't fix it.

**Full Disk Access grant gets wiped after every reboot.** Probably a TCC-database issue after a macOS point upgrade. Re-add the entries in Privacy & Security. If it recurs on a managed Mac, deploy the TCC profile via MDM instead.
