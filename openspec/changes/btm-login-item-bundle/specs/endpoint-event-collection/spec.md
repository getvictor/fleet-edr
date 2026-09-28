## MODIFIED Requirements

### Requirement: Launch-item registration event capture

The system SHALL emit a `btm_launch_item_add` event when launchd registers a launch item (a LaunchDaemon, LaunchAgent, or login item) via Background Task Management. The payload MUST carry the item type, the launch item path, the registered executable path when available, the MDM-managed flag, and the code-signing identity of the REGISTERED EXECUTABLE (`executable_code_signing`: team ID, signing ID, platform-binary flag) evaluated out-of-band, because the event provides code-signing for the instigator process but not for the to-be-launched executable.

Background Task Management reports an item registered through `SMAppService` relative to the app that registered it, and reports that app separately. The payload MUST carry that app as `app_url`, and the launch item path MUST be uploaded resolved against it, as an absolute `file://` URL. A login item, and an app added to the user's login items, have no registered executable path: the registered executable is the app bundle the item names (a helper inside the registering app for `item_type=login_item`, the app itself for `item_type=app`), and `executable_code_signing` MUST be that bundle's.

#### Scenario: A LaunchDaemon is registered via Background Task Management

- **GIVEN** the endpoint event capture is running
- **WHEN** launchd registers a system LaunchDaemon (for example via `launchctl bootstrap`)
- **THEN** the system emits a `btm_launch_item_add` event whose payload includes `item_type=daemon`, the launch item path, the registered executable path, the MDM-managed flag, and the registered executable's code-signing identity

#### Scenario: A login item is registered through SMAppService

- **GIVEN** the endpoint event capture is running
- **WHEN** an app registers a helper in its `Contents/Library/LoginItems/` as a login item
- **THEN** the uploaded `btm_launch_item_add` event has `item_type=login_item` and the registering app as `app_url`
- **AND** its launch item path is the helper bundle's absolute `file://` URL
- **AND** its `executable_code_signing` is the helper bundle's code-signing identity

#### Scenario: An app is added to the user's login items

- **GIVEN** the endpoint event capture is running
- **WHEN** an app is added to the user's login items, by itself through `SMAppService` or through the legacy login-items list
- **THEN** the uploaded `btm_launch_item_add` event has `item_type=app` and the app bundle's absolute `file://` URL as its launch item path
- **AND** its `executable_code_signing` is the app bundle's code-signing identity
