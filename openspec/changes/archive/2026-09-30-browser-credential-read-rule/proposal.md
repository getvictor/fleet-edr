## Why

Infostealers are the most common macOS threat, and their core behavior is reading a browser's saved passwords and cookies (MITRE T1555.003, issue #1187). The security extension now reports another program's open of those files as an `open` event; nothing raises an alert on it.

## What changes

- A new rule, `credential_browser_store_read` (high), fires on an `open` of a Chrome, Brave, Edge, Arc, Vivaldi or Firefox credential file by a process other than that browser, naming the process, the browser and the file.
- It skips a process signed by the browser's own team, as a second check behind the extension's, and Apple's Time Machine and Spotlight services, judged by their platform-qualified signing identifiers.
- An operator waives an opener by its path, team, team-qualified signing identifier or cdhash. One alert is raised per process.

## Not changed

Safari's cookies, browsers at custom profile locations, and Chromium browsers not listed are not covered.
