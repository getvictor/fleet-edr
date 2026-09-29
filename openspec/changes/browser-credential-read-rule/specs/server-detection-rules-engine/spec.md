## ADDED Requirements

### Requirement: Browser credential theft is reported

The `credential_browser_store_read` rule SHALL fire on an `open` event whose path lies in the profile directory of Chrome, Brave, Edge, Arc, Vivaldi or Firefox and ends in one of that browser's credential file names (for a Chromium browser `Login Data`, `Login Data For Account`, `Web Data`, `Cookies` or `Local State`; for Firefox `logins.json`, `key4.db` or `cookies.sqlite`), naming the opening process, the browser and the file, and linking the finding to the process. It SHALL NOT fire when the opening process is signed by the team that signs that browser, or when its platform-qualified signing identifier is one of Time Machine's or Spotlight's. An exclusion for the rule SHALL suppress it by the opener's path, team, team-qualified signing identifier or cdhash.

#### Scenario: Another program opening a credential store fires

- **GIVEN** `cp` opening Chrome's `Login Data`, `Network/Cookies` or `Local State`, Firefox's `key4.db`, or Arc's `Web Data`
- **WHEN** detection evaluates each event
- **THEN** `credential_browser_store_read` raises a high-severity finding naming the process, the browser and the file

#### Scenario: The browser and Apple's backup and indexing services do not fire

- **GIVEN** Chrome opening its own `Login Data`, Firefox its own `logins.json`, Time Machine a Chrome cookie store, and `cp` opening a profile file that is not a credential store, a journal file beside one, or a `Login Data` outside a browser directory
- **WHEN** detection evaluates the events
- **THEN** no finding is raised
- **AND** Chrome opening Firefox's store, and a non-Apple binary claiming Time Machine's signing identifier, each still fire

#### Scenario: An opener is waived by its signer or path

- **GIVEN** an exclusion for the rule naming a backup tool's team, its team-qualified signing identifier, or a path glob over its bundle
- **WHEN** detection evaluates the tool opening a credential store
- **THEN** no finding is raised
- **AND** the same team excluded only for another rule does not suppress it
