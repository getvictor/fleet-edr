# Fleet MDM deployment

This is the Fleet-specific recipe for deploying the Fleet EDR agent to a
fleet of Macs. For the vendor-neutral contract (what the three artifacts
are and why) see [mdm-deployment.md](mdm-deployment.md).

Fleet and Fleet EDR are independent products. Fleet owns MDM + osquery;
Fleet EDR owns the endpoint security / detection data plane. The contact
between them is a deployment contract: Fleet delivers a signed `.pkg`,
two `.mobileconfig` profiles, and an install script. The EDR server
receives events from the resulting agents directly, not via Fleet.

## Prerequisites

- A Fleet server (version 4.48+) with MDM turned on and an Apple APNs +
  ABM (Apple Business Manager) push certificate uploaded. Macs must be
  ADE-enrolled or manually UAMDM-enrolled. Without UAMDM, macOS refuses
  the restricted payloads in our two profiles.
- `fleetctl` installed locally and authenticated (`fleetctl login`). The
  UI also works; this doc uses `fleetctl` because every step is
  reproducible.
- A running Fleet EDR server with a known enroll secret (the value in
  `./secrets/enroll_secret` from [install-server.md](install-server.md)).
- Downloaded release artifacts from
  [GitHub Releases](https://github.com/getvictor/fleet-edr/releases):
  - `fleet-edr-<version>.pkg`
  - `edr-system-extension.mobileconfig`
  - `edr-tcc-fda.mobileconfig`
  - `SHA256SUMS`

## Scope

Decide which Macs get the EDR before you start. In Fleet this is a
**team**. Every artifact below scopes to a team; to ship to "all Macs",
use the No-team special team.

```sh
fleetctl get teams
# Pick the team id + name. Examples below assume team "EDR pilot".
```

## Step 1: push the two profiles

Fleet's "custom settings" feature sends a `.mobileconfig` verbatim to the
Macs in a team's scope. Both of our profiles go here.

```sh
fleetctl apply -f - <<'EOF'
apiVersion: v1
kind: team
spec:
  team:
    name: EDR pilot
    mdm:
      macos_settings:
        custom_settings:
          - path: ./edr-system-extension.mobileconfig
          - path: ./edr-tcc-fda.mobileconfig
EOF
```

Fleet hashes each file and pushes it as an MDM profile install command.
The osquery agent (`fleetd`) reports profile install status back to
Fleet, so you can watch progress in **Controls > macOS settings** in the
UI or via `fleetctl get mdm profile-status`.

Each profile has a `PayloadIdentifier` that Fleet uses to track
uniqueness; keep the filenames as shipped so future `fleetctl apply`
runs replace-in-place rather than creating duplicates.

Verify on a target Mac:

```sh
sudo profiles list | grep fleetdm
# Expect:
#   com.fleetdm.edr.profile.system-extension
#   com.fleetdm.edr.profile.tcc-fda
```

## Step 2: upload the pkg + install script together

Fleet's software installer bundles a `.pkg` and an optional
pre-install script into a single "software package". We use that bundle
to ship the pkg AND the enroll-secret write in one deploy step.

Write the install script to a local file:

```sh
cat > fleet-edr-install.sh <<'EOF'
#!/bin/sh
set -eu

# Fleet's agent expands $FLEET_SECRET_* into the value of the
# corresponding custom variable at runtime. Define them at
# Settings > Integrations > MDM > Variables (or via fleetctl).
EDR_SERVER_URL="${FLEET_SECRET_EDR_SERVER_URL:-https://edr.example.com}"
EDR_ENROLL_SECRET="$FLEET_SECRET_EDR_ENROLL_SECRET"

install -m 0600 /dev/null /etc/fleet-edr.conf
cat > /etc/fleet-edr.conf <<CONF
EDR_SERVER_URL=$EDR_SERVER_URL
EDR_ENROLL_SECRET=$EDR_ENROLL_SECRET
CONF
EOF
```

Define the two secrets in Fleet so the script can reference them without
ever committing them to your repo. In the Fleet UI:

1. **Settings > Integrations > MDM > Custom variables**.
2. Add `EDR_SERVER_URL` with your server's URL.
3. Add `EDR_ENROLL_SECRET` with the value from
   `./secrets/enroll_secret` on the server.

Upload the pkg + script bundle:

```sh
fleetctl software add \
    --team "EDR pilot" \
    --path fleet-edr-v0.1.0.pkg \
    --pre-install-script fleet-edr-install.sh
```

Fleet runs the pre-install script first, then `installer -pkg` against
the uploaded `.pkg`. The script writes the config file the pkg's
postinstall step needs, so the sequencing is guaranteed (unlike generic
MDMs where you fight with install-script ordering).

Verify on a target Mac after Fleet runs the install:

```sh
# Daemon loaded and running
sudo launchctl print system/com.fleetdm.edr.agent | grep 'state ='
# Expect: state = running

# Sysext activated silently (thanks to the system-extension profile)
systemextensionsctl list | grep fleetdm
# Expect: * * FDG8Q7N4CC com.fleetdm.edr.securityextension ... [activated enabled]

# Agent enrolled with the server
sudo tail -n 20 /var/log/fleet-edr-agent.log | grep enrolled
```

## Step 3: confirm in the EDR admin UI

Open `https://<your-edr-server>/ui/`. The Macs that finished the
Fleet-driven install appear on the Hosts page with their hardware UUID
and a `last_seen` timestamp that updates every ~5s.

## Upgrade

Push a new pkg version by re-running `fleetctl software add` with the
newer file. Fleet replaces the software package in-place; the install
script doesn't change.

```sh
fleetctl software add \
    --team "EDR pilot" \
    --path fleet-edr-v0.1.1.pkg \
    --pre-install-script fleet-edr-install.sh
```

On each Mac the EDR pkg's preinstall stops the old daemon and the
postinstall starts the new one. The host token at
`/var/db/fleet-edr/enrolled.plist` survives the upgrade so agents don't
re-enroll.

If the new release changes one of the two `.mobileconfig` profiles,
push the new profile first (Step 1), wait for Fleet to confirm
delivery, then push the new pkg. The reverse order risks an activation
prompt if the pkg expects a payload that hasn't landed yet.

## Uninstall

Fleet's software UI supports uninstall scripts on a software package.
Add one:

```sh
cat > fleet-edr-uninstall.sh <<'EOF'
#!/bin/sh
set -eu
if [ -x "/Library/Application Support/com.fleetdm.edr/uninstall.sh" ]; then
    "/Library/Application Support/com.fleetdm.edr/uninstall.sh"
fi
EOF

fleetctl software add \
    --team "EDR pilot" \
    --path fleet-edr-v0.1.1.pkg \
    --pre-install-script fleet-edr-install.sh \
    --uninstall-script fleet-edr-uninstall.sh
```

To remove the profiles as well, edit the team's YAML and drop the two
`custom_settings` entries. Fleet removes the profiles from each Mac on
the next check-in; macOS tears down the TCC grants and sysext
allow-list within minutes.

## Rotate the enroll secret

The secret is stored as a Fleet custom variable (`FLEET_SECRET_EDR_ENROLL_SECRET`),
not hardcoded in the install script.

1. Generate a new value on the EDR server and write it to
   `./secrets/enroll_secret` (see
   [install-server.md](install-server.md#rotate-secrets)).
2. Restart the server so the new secret takes effect:
   `docker compose restart server`.
3. In Fleet: **Settings > Integrations > MDM > Custom variables**,
   update `EDR_ENROLL_SECRET` to the new value.
4. Re-run `fleetctl software add` so Fleet re-pushes the install script
   with the new variable value.

Existing hosts keep working because they authenticate with their
per-host token, not the enroll secret. The rotated secret only matters
the next time a brand-new Mac enrolls.

## Troubleshoot

**Profile stuck at "pending" in Fleet.**
The Mac isn't UAMDM-enrolled. Open **Hosts > <host> > MDM** in Fleet;
if it says "Enrolled (manual)" without UAMDM, re-enroll via ADE or
walk the user through the manual UAMDM prompt in System Settings.
Restricted payloads will not install otherwise.

**Software package says "installed" but the pkg never ran.**
Fleet considers a package "installed" once the pre-install script
succeeds and the installer command starts. If the pkg itself fails,
check **Hosts > <host> > Scripts** for the installer stdout/stderr.

**Agent enrolls but events don't appear in the EDR UI.**
The TCC FDA profile didn't reach the Mac. Check
`sudo profiles list | grep tcc-fda` on the host; if missing, re-scope
the profile to the team. After it lands, kick the daemon:
`sudo launchctl kickstart -k system/com.fleetdm.edr.agent`.

**Install script runs but `/etc/fleet-edr.conf` is empty or missing a
variable.**
A custom variable referenced by the script isn't defined in Fleet. The
script uses `set -eu`, so an unset `FLEET_SECRET_*` fails fast; check
**Settings > Integrations > MDM > Custom variables**.
