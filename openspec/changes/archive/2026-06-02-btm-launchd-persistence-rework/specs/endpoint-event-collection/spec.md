# Endpoint Event Collection Specification (delta)

## ADDED Requirements

### Requirement: Launch-item registration event capture

The system SHALL emit a `btm_launch_item_add` event when launchd registers a launch item (a LaunchDaemon, LaunchAgent,
or login item) via Background Task Management. The payload MUST carry the item type, the launch item path, the registered
executable path when available, the MDM-managed flag, and the code-signing identity of the REGISTERED EXECUTABLE
(`executable_code_signing`: team ID, signing ID, platform-binary flag) evaluated out-of-band, because the event provides
code-signing for the instigator process but not for the to-be-launched executable.

#### Scenario: A LaunchDaemon is registered via Background Task Management

- **GIVEN** the endpoint event capture is running
- **WHEN** launchd registers a system LaunchDaemon (for example via `launchctl bootstrap`)
- **THEN** the system emits a `btm_launch_item_add` event whose payload includes `item_type=daemon`, the launch item
  path, the registered executable path, the MDM-managed flag, and the registered executable's code-signing identity
