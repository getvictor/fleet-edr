# Web UI

## ADDED Requirements

### Requirement: Abbreviated table figures are reachable without a pointer

Where a table cell abbreviates a figure and keeps the precise value elsewhere, the precise value SHALL be reachable by keyboard and by touch, not by pointer hover alone. The cell SHALL keep its abbreviated form, because a table read a thousand rows at a time has to stay scannable.

The precise value SHALL remain available to assistive technology whether or not it has been revealed, and SHALL be associated with the control that reveals it. A disclosure that renders the value only while expanded would remove what a hover tooltip's accessible label already provided, which would trade one population's access for another's.

Where several columns in the same table abbreviate, they SHALL use one mechanism, so adjacent columns do not answer the same gesture differently.

#### Scenario: The precise figure opens without a pointer

- **GIVEN** a table cell showing an abbreviated figure
- **WHEN** an operator reaches the cell's control by keyboard and activates it
- **THEN** the precise figure becomes visible
- **AND** the same activation by tap has the same effect

#### Scenario: Assistive technology has the figure before it is revealed

- **GIVEN** a table cell showing an abbreviated figure that has not been expanded
- **WHEN** assistive technology reads the cell's control
- **THEN** the precise figure is available as the control's description
