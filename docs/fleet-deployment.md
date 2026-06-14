# Fleet MDM deployment

This is the Fleet-specific recipe for deploying the Fleet EDR agent to a fleet of Macs. For the vendor-neutral contract (what the three artifacts are and why) see [mdm-deployment.md](mdm-deployment.md).

Fleet and Fleet EDR are independent products. Fleet owns MDM + osquery; Fleet EDR owns the endpoint security / detection data plane. The contact between them is a deployment contract: Fleet delivers a signed `.pkg`, two `.mobileconfig` profiles, and an install script. The EDR server receives events from the resulting agents directly, not via Fleet.

## Prerequisites

- A Fleet server (version 4.86+) with MDM turned on and an Apple APNs + ABM (Apple Business Manager) push certificate uploaded. Macs must be ADE-enrolled or manually UAMDM-enrolled. Without UAMDM, macOS refuses the restricted payloads in our two profiles.
- `fleetctl` installed locally and authenticated (`fleetctl login`). The UI also works; this doc uses `fleetctl` because every step is reproducible.
- A running Fleet EDR server with a known enroll secret (the value in `./secrets/enroll_secret` from [install-server.md](install-server.md)).
- Downloaded release artifacts from [GitHub Releases](https://github.com/getvictor/fleet-edr/releases):
  - `fleet-edr-<version>.pkg`
  - `edr-system-extension.mobileconfig`
  - `edr-tcc-fda.mobileconfig`
  - `SHA256SUMS`

## Scope

Decide which Macs get the EDR before you start. In Fleet this grouping is a **fleet**. Every artifact below scopes to a fleet; to cover Macs you haven't put in a named fleet, use the built-in Unassigned fleet.

```sh
fleetctl get fleets
# Pick the fleet id + name. Examples below assume fleet "EDR pilot".
```

## Step 1: push the two profiles

Fleet's "custom settings" feature sends a `.mobileconfig` verbatim to the Macs in a fleet's scope. Both of our profiles go here.

```sh
fleetctl apply -f - <<'EOF'
apiVersion: v1
kind: fleet
spec:
  fleet:
    name: EDR pilot
    mdm:
      macos_settings:
        custom_settings:
          - path: ./edr-system-extension.mobileconfig
          - path: ./edr-tcc-fda.mobileconfig
EOF
```

Fleet hashes each file and pushes it as an MDM profile install command. The osquery agent (`fleetd`) reports profile install status back to Fleet, so you can watch progress in **Controls > macOS settings** in the UI or via `fleetctl get mdm profile-status`.

Each profile has a `PayloadIdentifier` that Fleet uses to track uniqueness; keep the filenames as shipped so future `fleetctl apply` runs replace-in-place rather than creating duplicates.

Verify on a target Mac:

```sh
sudo profiles list | grep fleetdm
# Expect:
#   com.fleetdm.edr.profile.system-extension
#   com.fleetdm.edr.profile.tcc-fda
```

## Step 2: add the pkg with a custom install script

Fleet's software packages carry an `install_script` that replaces the default install command. We use that script to write the enroll-secret config AND run the installer in one step, so the sequencing is guaranteed (unlike generic MDMs where you fight with install-script ordering). Fleet has no separate pre-install script concept; the only pre-install hook is `pre_install_query`, an osquery SQL condition, which we don't need.

Write the install and uninstall scripts to local files:

```sh
cat > fleet-edr-install.sh <<'EOF'
#!/bin/sh
set -eu

# Fleet's agent expands FLEET_SECRET_* into the value of the
# corresponding custom variable at runtime. Define them at
# Settings > Integrations > MDM > Variables (or via fleetctl).
EDR_SERVER_URL="$FLEET_SECRET_EDR_SERVER_URL"
EDR_ENROLL_SECRET="$FLEET_SECRET_EDR_ENROLL_SECRET"

install -m 0600 /dev/null /etc/fleet-edr.conf
cat > /etc/fleet-edr.conf <<CONF
EDR_SERVER_URL=$EDR_SERVER_URL
EDR_ENROLL_SECRET=$EDR_ENROLL_SECRET
CONF

# $INSTALLER_PATH is set by fleetd to the downloaded pkg's location.
installer -pkg "$INSTALLER_PATH" -target /
EOF

cat > fleet-edr-uninstall.sh <<'EOF'
#!/bin/sh
set -eu
if [ -x "/Library/Application Support/com.fleetdm.edr/uninstall.sh" ]; then
    "/Library/Application Support/com.fleetdm.edr/uninstall.sh"
fi
EOF
```

Define the two secrets in Fleet so the script can reference them without ever committing them to your repo. In the Fleet UI:

1. **Settings > Integrations > MDM > Custom variables**.
2. Add `EDR_SERVER_URL` with your server's URL.
3. Add `EDR_ENROLL_SECRET` with the value from `./secrets/enroll_secret` on the server.

**Via fleetctl:** extend the same fleet spec from Step 1 with a `software` section. The CLI path references the pkg by URL (Fleet downloads it server-side); point it at the GitHub Release asset and pin the hash from `SHA256SUMS`:

```sh
fleetctl apply -f - <<'EOF'
apiVersion: v1
kind: fleet
spec:
  fleet:
    name: EDR pilot
    software:
      packages:
        - url: https://github.com/getvictor/fleet-edr/releases/download/v0.1.0/fleet-edr-v0.1.0.pkg
          hash_sha256: <sha256 of the pkg, from SHA256SUMS>
          install_script:
            path: ./fleet-edr-install.sh
          uninstall_script:
            path: ./fleet-edr-uninstall.sh
EOF
```

**Via the Fleet UI** (this path accepts a local pkg file instead of a URL):

1. **Software > Add software > Custom package**, with the "EDR pilot" fleet selected in the scope picker.
2. **Choose file** and select `fleet-edr-v0.1.0.pkg`.
3. Expand **Advanced options** and replace the default install script with the contents of `fleet-edr-install.sh`; paste `fleet-edr-uninstall.sh` into the uninstall script field.
4. **Add software**.

Adding the package only makes it available to the fleet; nothing installs yet. An install triggers per host in one of three ways:

- **Manually**: **Hosts > \<host\> > Software**, find Fleet EDR, **Actions > Install**.
- **Self-service**: if enabled on the package, end users install it from Fleet Desktop's Self-service tab.
- **Automatic install**: check **Automatic install** when adding the package in the UI. Fleet creates a policy that installs the EDR on every in-scope host that doesn't have it, which is what you want for a fleet-wide rollout. The checkbox exists only on the add flow (not edit), and the `fleetctl apply` YAML path doesn't expose it; to automate a CLI-managed package, attach it to a policy automation instead.

When an install fires, fleetd downloads the pkg to the host and runs the install script, which writes the config file the pkg's postinstall step needs and then invokes `installer` itself.

Verify on a target Mac after Fleet runs the install:

```sh
# Daemon loaded and running
sudo launchctl print system/com.fleetdm.edr.agent | grep 'state ='
# Expect: state = running

# Sysext activated silently (the pkg's activation LaunchAgent + the
# system-extension profile). If this prints nothing and nobody was logged
# in when the pkg installed, activation fires at the next login.
systemextensionsctl list | grep fleetdm
# Expect: * * FDG8Q7N4CC com.fleetdm.edr.securityextension ... [activated enabled]

# Agent enrolled with the server (grep the whole log; enrollment happens
# once at startup and scrolls out of a tail quickly)
grep "agent enrolled" /var/log/fleet-edr-agent.log
```

## Step 3: confirm in the EDR admin UI

Open `https://<your-edr-server>/ui/`. The Macs that finished the Fleet-driven install appear on the Hosts page with their hardware UUID and a `last_seen` timestamp that updates every ~5s.

## Upgrade

**Via fleetctl:** bump the `url` and `hash_sha256` in the Step 2 spec to the new release and re-apply. Fleet replaces the software package in-place; the install script doesn't change.

```yaml
- url: https://github.com/getvictor/fleet-edr/releases/download/v0.1.1/fleet-edr-v0.1.1.pkg
  hash_sha256: <sha256 of the new pkg>
  install_script:
    path: ./fleet-edr-install.sh
  uninstall_script:
    path: ./fleet-edr-uninstall.sh
```

**Via the Fleet UI:** **Software**, select the Fleet EDR package (with the "EDR pilot" fleet in scope), then **Actions > Edit**, choose the newer pkg file, and save. The scripts carry over unless you change them.

On each Mac the EDR pkg's preinstall stops the old daemon and the postinstall starts the new one. The host token at `/var/db/fleet-edr/enrolled.plist` survives the upgrade so agents don't re-enroll.

If the new release changes one of the two `.mobileconfig` profiles, push the new profile first (Step 1), wait for Fleet to confirm delivery, then push the new pkg. The reverse order risks an activation prompt if the pkg expects a payload that hasn't landed yet.

## Uninstall

The uninstall script attached in Step 2 wraps the pkg's bundled `uninstall.sh`, which removes the daemon, host app, and system extension. Trigger it per host in the Fleet UI: **Hosts > \<host\> > Software**, find Fleet EDR, then **Actions > Uninstall**. There is no fleetctl command for a per-host uninstall; script results land under **Hosts > \<host\> > Activity**.

To remove the profiles as well, edit the fleet's YAML and drop the two `custom_settings` entries. Fleet removes the profiles from each Mac on the next check-in; macOS tears down the TCC grants and sysext allow-list within minutes.

## Rotate the enroll secret

The secret is stored as a Fleet custom variable (`FLEET_SECRET_EDR_ENROLL_SECRET`), not hardcoded in the install script.

1. Generate a new value on the EDR server and write it to `./secrets/enroll_secret` (see [install-server.md](install-server.md#rotate-secrets)).
2. Restart the server so the new secret takes effect: `docker compose restart server`.
3. In Fleet: **Settings > Integrations > MDM > Custom variables**, update `EDR_ENROLL_SECRET` to the new value.

There is nothing to re-upload: `$FLEET_SECRET_*` variables expand when the install script runs on a host, so the next install picks up the rotated value automatically.

Existing hosts keep working because they authenticate with their per-host token, not the enroll secret. The rotated secret only matters the next time a brand-new Mac enrolls.

## Troubleshoot

**"Couldn't add. Configuration profiles can't be signed. Fleet will sign the profile for you."** Fleet signs profiles itself at delivery and rejects pre-signed uploads. The released profiles ship unsigned, so uploading them as shipped avoids this. If you hit it, the profile was signed before upload (by you or your tooling): re-download the unsigned profiles from the latest release and upload those.

**Profile stuck at "pending" in Fleet.** The Mac isn't UAMDM-enrolled. Open **Hosts > <host> > MDM** in Fleet; if it says "Enrolled (manual)" without UAMDM, re-enroll via ADE or walk the user through the manual UAMDM prompt in System Settings. Restricted payloads will not install otherwise.

**Software install reports "failed" or the pkg never ran.** The install script owns both the config write and the `installer -pkg` call, so its exit status is the install result. Check **Hosts > \<host\> > Activity** and open the install details for the script's stdout/stderr; a non-zero exit from `installer` (or an unset `$FLEET_SECRET_*` variable tripping `set -eu`) shows up there.

**Agent enrolls but events don't appear in the EDR UI.** The TCC FDA profile didn't reach the Mac. Check `sudo profiles list | grep tcc-fda` on the host; if missing, re-scope the profile to the fleet. After it lands, kick the daemon: `sudo launchctl kickstart -k system/com.fleetdm.edr.agent`.

**Install script runs but `/etc/fleet-edr.conf` is empty or missing a variable.** A custom variable referenced by the script isn't defined in Fleet. The script uses `set -eu`, so an unset `FLEET_SECRET_*` fails fast; check **Settings > Integrations > MDM > Custom variables**.
