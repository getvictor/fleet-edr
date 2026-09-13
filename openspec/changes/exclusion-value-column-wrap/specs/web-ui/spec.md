## ADDED Requirements

### Requirement: Long exclusion values wrap within a capped Value column

The detection tuning view's exclusion table SHALL cap the width of its Value column, and a value longer than the cap SHALL wrap onto further lines inside the column rather than widen the table. An exclusion value is commonly a path or glob with no spaces, so without a cap a single long value sets the table's width and pushes the Reason, Expires and Created by columns out of view.

The column SHALL be as wide as its longest value up to the cap, so a long value wraps at the cap rather than well short of it. A value is not truncated: every character stays visible, because the end of a glob is the part that names what is trusted.

#### Scenario: A long value wraps at the cap

- **GIVEN** an exclusion whose value is a 70-character path glob with no spaces
- **WHEN** the detection tuning view renders the exclusion table at a 1280px-wide viewport
- **THEN** the value is shown at the column's cap width and spans more than one line
- **AND** the table does not scroll horizontally
