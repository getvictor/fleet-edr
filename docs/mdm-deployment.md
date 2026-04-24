# MDM deployment (vendor-neutral)

Fleet EDR is designed to ship through any MDM that can deliver a
`.pkg` + two `.mobileconfig` profiles + a one-line install script.
This works with Jamf Pro, Kandji, Intune, mosyle, Fleet, and any
equivalent platform.

For the Fleet-specific recipe see [fleet-deployment.md](fleet-deployment.md).
For single-Mac eval without an MDM see [install-agent-manual.md](install-agent-manual.md).

## The deployment contract

Three artifacts, delivered in this order:

1. **Two signed `.mobileconfig` profiles** pushed via MDM "custom
   settings". Pre-approves the ES system extension and grants Full Disk
   Access. These must arrive BEFORE the pkg so the sysext activates
   silently on install.
2. **An install script** your MDM runs before the pkg installer. It
   writes `/etc/fleet-edr.conf` with the enroll secret + server URL.
3. **The signed `.pkg`** pushed via MDM "software installer".

Every MDM exposes these three primitives under different names. The
mapping is in the vendor-specific section at the bottom.

## Why this shape

Restricted Apple payload types (`com.apple.system-extension-policy`,
`com.apple.TCC.configuration-profile-policy`) require delivery by an
MDM the Mac has user-approved. Any other delivery path (web download,
`profiles install`) is rejected on modern macOS. That's why the two
profiles MUST come from your MDM; there's no workaround.

The install script is the clean hand-off for the enroll secret. Your
MDM knows the secret (you configured it as an MDM variable); the pkg
itself is customer-agnostic so it can ship from our Releases page
unmodified. The script bridges the gap by dropping the secret into
`/etc/fleet-edr.conf` on each Mac.

## Artifacts

All three files live on the [GitHub Release page](https://github.com/getvictor/fleet-edr/releases)
for each version:

| Artifact | Filename on Release | Notes |
|---|---|---|
| Pkg installer | `fleet-edr-<version>.pkg` | Signed with Developer ID Installer, notarized, stapled |
| System-extension profile | `edr-system-extension.mobileconfig` | Signed with Developer ID Installer (CMS) |
| TCC FDA profile | `edr-tcc-fda.mobileconfig` | Signed with Developer ID Installer (CMS) |
| Checksums | `SHA256SUMS` | Verify downloads before uploading to your MDM |

Download all four, verify checksums, then upload the three artifacts
into your MDM.

```sh
cd ~/Downloads
curl -fLO https://github.com/getvictor/fleet-edr/releases/download/v0.1.0/fleet-edr-v0.1.0.pkg
curl -fLO https://github.com/getvictor/fleet-edr/releases/download/v0.1.0/edr-system-extension.mobileconfig
curl -fLO https://github.com/getvictor/fleet-edr/releases/download/v0.1.0/edr-tcc-fda.mobileconfig
curl -fLO https://github.com/getvictor/fleet-edr/releases/download/v0.1.0/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
# All three artifacts should print "OK".
```

## Step 1: push the system-extension profile

Upload `edr-system-extension.mobileconfig` to your MDM as a custom
configuration profile and scope it to the Macs that will run the agent.

What the profile does: pre-approves the bundle ID
`com.fleetdm.edr.securityextension` under team ID `FDG8Q7N4CC` in the
`com.apple.system-extension-policy` payload. When the pkg installer runs
the host app's sysext-activation request, macOS finds the pre-approval,
skips the user prompt, and activates the sysext immediately.

Verify on a target Mac:

```sh
profiles list | grep fleetdm
# Expect two profiles once both are pushed:
#   com.fleetdm.edr.profile.system-extension
#   com.fleetdm.edr.profile.tcc-fda
```

## Step 2: push the TCC FDA profile

Upload `edr-tcc-fda.mobileconfig` the same way.

What the profile does: grants Full Disk Access to the agent
(`/usr/local/bin/fleet-edr-agent`) and the sysext
(`com.fleetdm.edr.securityextension`) via a
`com.apple.TCC.configuration-profile-policy` payload. Without it, the
sysext's `es_new_client` call returns `ERR_NOT_PERMITTED` and no events
flow.

Verify after the pkg installs:

```sh
# The sysext needs to create an ES client; failures would show up here.
sudo tail -n 50 /var/log/fleet-edr-agent.log | grep -E 'ES|receiver'
# Expect: receiver connected ... (FDG8Q7N4CC.com.fleetdm.edr.securityextension.xpc)
```

## Step 3: install script

Your MDM must run this script BEFORE the pkg installer. It writes the
enroll secret + server URL into `/etc/fleet-edr.conf`. The pkg's
postinstall starts the agent, which reads that file and enrolls.

```sh
#!/bin/sh
set -eu

# Fill these in from your MDM's variables / secrets. Never hardcode.
EDR_SERVER_URL="${EDR_SERVER_URL:-https://edr.example.com}"
EDR_ENROLL_SECRET="${EDR_ENROLL_SECRET:?EDR_ENROLL_SECRET must be set}"

# Optional: pin the server's TLS cert by SHA-256 fingerprint.
# Useful for self-signed certs in isolated deployments.
# EDR_SERVER_FINGERPRINT="sha256//..."

install -m 0644 /dev/null /etc/fleet-edr.conf
cat > /etc/fleet-edr.conf <<EOF
EDR_SERVER_URL=$EDR_SERVER_URL
EDR_ENROLL_SECRET=$EDR_ENROLL_SECRET
${EDR_SERVER_FINGERPRINT:+EDR_SERVER_FINGERPRINT=$EDR_SERVER_FINGERPRINT}
EOF
```

`$EDR_ENROLL_SECRET` is the value from your server's
`./secrets/enroll_secret`. Store it as an MDM secret variable; don't
inline it in the script in your MDM repo.

## Step 4: push the pkg

Upload `fleet-edr-v<version>.pkg` to your MDM as a software installer
and scope to the same Macs.

The pkg's install flow:

1. `installationCheck()` validates the Mac is Apple Silicon + macOS 13+.
2. Preinstall script stops any existing `com.fleetdm.edr.agent`
   LaunchDaemon and deactivates any prior sysext (idempotent; no-op on
   fresh installs).
3. Payload lands under `/usr/local/bin`, `/Applications`,
   `/Library/LaunchDaemons`, `/Library/Application Support/com.fleetdm.edr`.
4. Postinstall script loads the LaunchDaemon
   (`launchctl bootstrap system ...`) and kickstarts it. The agent reads
   `/etc/fleet-edr.conf`, enrolls, starts polling.
5. On first agent-to-sysext XPC call, the host app triggers sysext
   activation. Thanks to Step 1's profile, this is silent.

Verify on a target Mac:

```sh
# Daemon loaded and running
sudo launchctl print system/com.fleetdm.edr.agent | grep 'state ='
# Expect: "state = running"

# Sysext activated
systemextensionsctl list | grep fleetdm
# Expect a row ending "[activated enabled]"

# Recent log
sudo tail -n 20 /var/log/fleet-edr-agent.log
# Expect: "agent enrolled" + "commander polling" lines
```

## Verify in the admin UI

Log into the Fleet EDR server's admin UI at
`https://<your-server>/ui/`. The Macs you pushed to appear on the Hosts
page with:

- Hostname
- Hardware UUID
- Agent version
- "last_seen" timestamp that updates every ~5s

Pick any host and view its process tree; executions from that Mac
appear within seconds of happening.

## Upgrade

Push the newer `.pkg` via your MDM. Same scope. The agent's preinstall
stops the old daemon, postinstall starts the new one, and the persisted
token at `/var/db/fleet-edr/enrolled.plist` survives so enrollments
don't churn.

If a new version changes the two profiles (rare), push the new ones
first, then the new pkg. Profile changes are live immediately; pkg
changes require the upgrade cycle.

## Uninstall via MDM

Push this as a run-script action:

```sh
#!/bin/sh
set -eu
if [ -x "/Library/Application Support/com.fleetdm.edr/uninstall.sh" ]; then
    "/Library/Application Support/com.fleetdm.edr/uninstall.sh"
fi
```

The uninstaller removes all binaries, LaunchDaemons, `/var/db/fleet-edr`,
and `/var/log/fleet-edr-agent.log`. It preserves `/etc/fleet-edr.conf`
so a future reinstall picks up the same enroll config. If you want a
truly clean slate, add `rm -f /etc/fleet-edr.conf` to the script above.

The sysext deactivation happens automatically via the uninstaller, which
reads the installed app's team ID from its codesign output. This keeps
the uninstaller working even if you re-signed the pkg with a different
team ID in a fork.

To also remove the MDM profiles, delete them from your MDM's custom
settings scope; the OS tears down the TCC grants + sysext allow-list
within minutes.

## Vendor-specific notes

### Jamf Pro

- Pkg upload: **Settings > Computer Management > Packages**. Upload,
  then assign via a **Policy** with the **Packages** payload.
- Profiles: **Configuration Profiles**, upload both `.mobileconfig`
  files. Scope to the same Smart Group as the policy.
- Install script: in the same policy, add a **Scripts** payload that
  runs BEFORE the package. Priority: **Before**.

### Kandji

- Pkg upload: **Library > Add new > Custom Apps**, upload pkg.
- Profiles: **Custom Profile** (one per mobileconfig).
- Install script: set as a **Pre-install script** on the custom app, or
  use a **Custom Script** library item scheduled to run before the
  custom app. Kandji runs library items in alphabetical order within a
  run interval; name your items accordingly
  (`01-edr-conf.sh`, `02-edr-app.pkg`).

### Microsoft Intune

- Pkg upload: **Apps > macOS > Add > Line-of-business app** (.pkg file).
  Intune requires `.pkg` files to be Developer ID-signed AND the install
  binaries to be in `/Applications` OR have `install-location="/"`.
  Ours does.
- Profiles: **Devices > Configuration profiles > Create profile >
  Templates > Custom**. Upload each `.mobileconfig`.
- Install script: **Devices > Scripts and remediations**. Run the
  install script in the same assignment group.

### mosyle

- Pkg upload: **Management > Applications > Applications Catalog > Add
  Enterprise Application**. Upload the `.pkg`.
- Profiles: **Management > Profiles > Custom Profiles**. Upload both
  `.mobileconfig` files and assign to the same device group.
- Install script: **Management > Commands > Scripts**. Schedule to run
  before the enterprise app install.

### Fleet MDM

See [fleet-deployment.md](fleet-deployment.md) for the full Fleet
workflow.

## Troubleshoot

**pkg installs but sysext stays in `activated waiting for user`.**
The system-extension profile hasn't reached the Mac yet, or it was
scoped differently. Check `profiles list | grep fleetdm` for the
`com.fleetdm.edr.profile.system-extension` entry. Re-scope + re-push if
missing.

**Agent log shows `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`.**
TCC FDA profile not pushed, or scoped to a different set of Macs than
the pkg. Check `profiles list` for `com.fleetdm.edr.profile.tcc-fda`.

**`installer: Error - Fleet EDR requires Apple Silicon (M1 or later).`**
Intel Mac scoped into the deployment. Narrow the scope by model type.

**Install script writes the conf file but the agent still fails to
enroll.**
The install script probably ran AFTER the pkg. Most MDMs run scripts + 
pkgs in parallel by default. Force "script first" via your MDM's
ordering controls (see vendor notes above).

**Agent enrolls but events don't appear in the admin UI.**
TCC FDA profile not applied to the sysext. The agent daemon ENROLLS
fine without FDA (it only talks HTTP); it's the sysext's ES client that
needs FDA to observe events. Verify TCC profile delivery, then
`sudo launchctl kickstart -k system/com.fleetdm.edr.agent` to force a
sysext reconnect.
