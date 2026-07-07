## ADDED Requirements

### Requirement: Host page time navigation

The host page SHALL present exactly one compact time control at rest, labeled with the active window ("Last 1 hour" for a relative window, a compact date-time span for an absolute one). Activating it SHALL open a popover offering relative quick-picks and an absolute from/to selection, either of which sets the window for every view on the page. The control SHALL include arrow affordances that shift the active window backward or forward by its own width, and a shifted window SHALL read as an absolute span. Arriving from an alert SHALL keep the existing anchored default (a wide window ending at the alert time).

The page SHALL render an activity histogram of process starts over the active window, and activating a histogram bucket SHALL narrow the active window to that bucket's span, reflected in the time control's label. The histogram SHALL come from the server-aggregated endpoint so it stays correct even when the rendered tree is truncated.

#### Scenario: One control at rest with relative and absolute selection

- **GIVEN** the host page is displayed
- **WHEN** the operator opens the time control and picks a relative quick-pick
- **THEN** the control's label names the relative window and the tree refetches for it
- **AND** picking an absolute from/to instead sets the window to that span and the label reads the span

#### Scenario: Shift arrows move the window by its width

- **GIVEN** an active one-hour window
- **WHEN** the operator activates the shift-back arrow
- **THEN** the active window becomes the previous hour as an absolute span
- **AND** the tree refetches for it

#### Scenario: Histogram bucket click narrows the window

- **GIVEN** the histogram shows a spike bucket
- **WHEN** the operator activates that bucket
- **THEN** the active window narrows to the bucket's span
- **AND** the time control's label reads the resulting absolute span

#### Scenario: Alert entry keeps its anchored window

- **GIVEN** the operator pivots from an alert
- **WHEN** the host page opens
- **THEN** the active window is the wide default ending at the alert's time, as before
