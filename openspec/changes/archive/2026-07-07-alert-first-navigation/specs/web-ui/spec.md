## ADDED Requirements

### Requirement: Alert list is the home view

The UI SHALL render the alert list as the home view of the authenticated application: navigating to the application root SHALL route to the alert list. When the operator's permission set does not confer the read action that gates the alert list, the root SHALL instead route to the first navigation entry the permission set does confer, in the navigation's display order, so the operator lands on a usable surface rather than a no-access state. The landing fallback SHALL be derived from the same permission-gated navigation model used to render the navigation entries, not from a separate role-to-route mapping.

#### Scenario: Root routes to the alert list

- **GIVEN** an authenticated operator whose permission set contains `alert.read`
- **WHEN** the operator navigates to the application root
- **THEN** the UI renders the alert list

#### Scenario: Operator without alert read lands on their first permitted surface

- **GIVEN** an authenticated operator whose permission set does not contain `alert.read`
- **WHEN** the operator navigates to the application root
- **THEN** the UI routes to the first navigation entry in display order that the operator's permission set confers
- **AND** no no-access state is rendered for the landing itself

### Requirement: Alert-first navigation order

The top navigation SHALL present its entries in the order Alerts, Hosts, Application control, Coverage, subject to the existing capability gating that hides entries the operator cannot read. The Hosts entry SHALL be highlighted as active on both the host list route and a host's process tree route.

#### Scenario: Navigation lists Alerts first

- **GIVEN** an authenticated operator whose permission set confers every navigation entry
- **WHEN** the authenticated application renders its navigation
- **THEN** the entries appear in the order Alerts, Hosts, Application control, Coverage

#### Scenario: Hosts entry active on host detail

- **GIVEN** an authenticated operator viewing a host's process tree page
- **WHEN** the navigation renders
- **THEN** the Hosts entry is highlighted as the active entry

### Requirement: Host list page

The UI SHALL render an enrolled host list on a dedicated hosts page reachable from the Hosts navigation entry. The page SHALL open with a fleet-overview summary of how many hosts are online, how many are offline, and the total host count, computed from the same online/offline classification used by the rows. Each row MUST identify the host by its enrollment hostname over its full hardware identifier (falling back to the hardware identifier alone when no enrollment hostname is known), show whether it is online or offline by comparing the host's last-seen timestamp to the current time, and show the host's running event count. A host MUST be classified online when its last-seen timestamp is within the last 5 minutes and offline otherwise. Activating a row MUST navigate to that host's process tree.

#### Scenario: Host list renders rows for enrolled hosts

- **GIVEN** the server has at least one enrolled host
- **WHEN** the operator opens the hosts page
- **THEN** the UI renders a row per host with the host identity, an online/offline pill, the event count, and a relative last-seen label

#### Scenario: Host list shows hostname and a fleet summary

- **GIVEN** the server returns hosts with enrollment hostnames, plus one host with no enrollment hostname
- **WHEN** the operator opens the hosts page
- **THEN** the UI shows a summary of online, offline, and total host counts
- **AND** each host cell shows the enrollment hostname over the full hardware identifier, and a host with no enrollment hostname shows the hardware identifier alone

#### Scenario: Clicking a host opens its process tree

- **GIVEN** the host list is displayed
- **WHEN** the operator activates a host row
- **THEN** the UI navigates to the process tree page scoped to that host id

## MODIFIED Requirements

### Requirement: Authenticated entry to the application

The UI SHALL probe the server's session endpoint on application load and SHALL render the login page when the probe indicates no active session. A successful login MUST establish a session and route the user to the application's home view; an invalid login MUST surface a generic error without revealing whether the email or the password was wrong. When the session lapses while the app is already open (an idle or absolute timeout, or a server-side revocation) and any subsequent request to the server is rejected as unauthenticated, the UI MUST return the operator to the login page rather than leaving them on a page that renders a raw transport error such as `API error: 401`. The redirect SHALL preserve the operator's current location so a successful re-login returns them to where they were.

#### Scenario: Anonymous user lands on the login page

- **GIVEN** a browser with no active session cookie
- **WHEN** the user navigates to the application
- **THEN** the UI renders the login page with the configured sign-in controls (SSO and a break-glass entry point)

#### Scenario: Successful login routes to the home view

- **GIVEN** the login page is displayed
- **WHEN** the user submits a valid email and password
- **THEN** the server establishes a session and the UI re-renders into the alert list as the home view

#### Scenario: Failed login shows a non-enumerating error

- **GIVEN** the login page is displayed
- **WHEN** the user submits credentials the server rejects
- **THEN** the UI shows a single generic error such as "invalid email or password"
- **AND** the UI does not distinguish between unknown email and wrong password

#### Scenario: Mid-session expiry returns the operator to login

- **GIVEN** an authenticated operator viewing any page after the load-time session probe has already succeeded
- **WHEN** a subsequent request to the server is rejected as unauthenticated because the session has expired or been revoked
- **THEN** the UI returns the operator to the login page rather than rendering a raw `API error: 401` on the current page
- **AND** the operator's current location is preserved so a successful re-login returns them to where they were

## REMOVED Requirements

### Requirement: Host list is the home view

**Reason**: The home view becomes the alert list to match the alert-first analyst workflow (epic #577, story #578). The host list's content behavior is unchanged and is re-specified under "Host list page" on a dedicated route.
**Migration**: Tests referencing `web-ui/host-list-is-the-home-view/<scenario>` move to `web-ui/host-list-page/<scenario>` (scenario headings are unchanged). Links and bookmarks to the application root now land on the alert list; the host list is directly reachable at its dedicated route.
