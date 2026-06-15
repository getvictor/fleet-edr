# Ship unsigned mobileconfig profiles: tasks

## 1. Pipeline

- [x] Rename `packaging/profiles/sign.sh` to `render.sh`; drop CMS signing and the `--dry-run` flag, keep template render + `plutil -lint`.
- [x] `release.yml`: both branches call `render.sh`; update the workflow header and the spec markers.
- [x] `release-secrets-check.yml`: replace the profile-signing step with a scratch-plist CMS sign that still exercises the Developer ID Installer private key.
- [x] `packaging/pkg/ci-setup.sh`: update the `-T /usr/bin/security` comment that referenced `profiles/sign.sh`.
- [x] Taskfile: drop `profiles:sign`, point `profiles:render` at `render.sh`.

## 2. Spec

- [x] `release-packaging` delta: profiles MUST ship unsigned; collapse the signed/unsigned scenarios into `profiles-are-rendered-unsigned` and update every marker.

## 3. Docs

- [x] `docs/README.md`: artifact list says unsigned.
- [x] `docs/mdm-deployment.md`: deployment contract says unsigned, MDM signs at delivery.
- [x] `docs/fleet-deployment.md`: troubleshooting entry for "Configuration profiles can't be signed" with the `security cms -D` strip for old releases.
