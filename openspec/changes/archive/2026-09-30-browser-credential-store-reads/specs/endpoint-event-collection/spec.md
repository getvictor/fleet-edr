## ADDED Requirements

### Requirement: Browser credential reads are reported

The security extension SHALL watch the credential files of Chrome, Brave, Edge, Arc, Vivaldi and Firefox in every profile of every home it reads from the directory service: for a Chromium browser, `Local State` and each profile's `Login Data`, `Login Data For Account`, `Web Data`, `Cookies` and `Network/Cookies`; for Firefox, each profile's `logins.json`, `key4.db` and `cookies.sqlite`. A Chromium profile is the `Default` directory or one named `Profile`, a space and a number written without leading zeros, as in `Profile 1`; a Firefox profile is a directory under `Profiles/` whose name holds a dot and does not start with one. It SHALL watch each file as a literal path and re-read the accounts and profiles at least every five minutes. When one browser directory holds more than 50 profiles, it SHALL watch that directory as a prefix instead of each file, report only opens of the credential files named here, and log that the directory held more. It SHALL report an open of a watched file as an `open` event carrying the open's access mode, unless the opening process is signed by the team that signs the browser owning the file.

#### Scenario: Every profile's credential files are watched

- **GIVEN** a home with Chrome profiles `Default` and `Profile 1`, a `System Profile` and a `Crashpad` directory beside them, and one Firefox profile
- **WHEN** the extension lists the files to watch
- **THEN** it watches Chrome's `Local State`, each of the two profiles' five credential files, and the Firefox profile's three, and nothing in `System Profile` or `Crashpad`

#### Scenario: The browser's own reads are not reported

- **GIVEN** an open of Chrome's `Login Data` by a process signed by Chrome's team, and one by an unsigned process, an Apple tool, or another browser
- **WHEN** the extension judges each open
- **THEN** it drops the first and reports the others

#### Scenario: A directory past the bound is watched whole

- **GIVEN** a Chrome directory holding `Default` and 50 numbered profiles, and a Firefox directory holding 50 decoy profiles beside the real one
- **WHEN** the extension lists the files to watch
- **THEN** it watches both directories as prefixes and neither's files as literal paths, and of the opens a prefix delivers it reports only those of credential files, so an open of the real Firefox profile's `logins.json` is reported and one of its `places.sqlite` is not
