## ADDED Requirements

### Requirement: Browser credential reads are reported

The security extension SHALL watch the credential files of Chrome, Brave, Edge, Arc, Vivaldi and Firefox in every profile of every home it reads from the directory service: for a Chromium browser, `Local State` and each profile's `Login Data`, `Login Data For Account`, `Web Data`, `Cookies` and `Network/Cookies`; for Firefox, each profile's `logins.json`, `key4.db` and `cookies.sqlite`. A Chromium profile is the `Default` directory or one named `Profile`, a space and a number written without leading zeros, as in `Profile 1`; a Firefox profile is a directory under `Profiles/` whose name holds a dot. It SHALL watch each file as a literal path and re-read the accounts and profiles at least every five minutes. It SHALL watch at most 50 profiles in one browser directory, keeping `Default` and then the lowest-numbered Chromium profiles, or the first Firefox profiles by name, and SHALL log that a directory held more. It SHALL report an open of a watched file as an `open` event carrying the open's access mode, unless the opening process is signed by the team that signs the browser owning the file.

#### Scenario: Every profile's credential files are watched

- **GIVEN** a home with Chrome profiles `Default` and `Profile 1`, a `System Profile` and a `Crashpad` directory beside them, and one Firefox profile
- **WHEN** the extension lists the files to watch
- **THEN** it watches Chrome's `Local State`, each of the two profiles' five credential files, and the Firefox profile's three, and nothing in `System Profile` or `Crashpad`

#### Scenario: The browser's own reads are not reported

- **GIVEN** an open of Chrome's `Login Data` by a process signed by Chrome's team, and one by an unsigned process, an Apple tool, or another browser
- **WHEN** the extension judges each open
- **THEN** it drops the first and reports the others

#### Scenario: Profiles past the bound are not watched

- **GIVEN** a Chrome directory holding `Default`, `Profile 1` to `Profile 3`, a thousand more numbered profiles, and names such as `Profile 01`
- **WHEN** the extension lists the files to watch
- **THEN** it watches 50 profiles, among them `Default` and `Profile 1` to `Profile 3`, none of the zero-padded names, and reports the directory as holding more than it watches
