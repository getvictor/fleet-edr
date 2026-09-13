## ADDED Requirements

### Requirement: Long exclusion values wrap within a capped Value column

The detection tuning view's exclusion table SHALL cap the width at which an exclusion value is laid out, and a value longer than the cap SHALL wrap onto further lines inside the Value column rather than widen the table. The column is that cap plus the table's ordinary cell padding. An exclusion value is commonly a path or glob with no spaces, so without a cap a single long value sets the table's width and pushes the Reason, Expires and Created by columns out of view.

A value SHALL be laid out as wide as it is up to the cap, so a long value wraps at the cap rather than well short of it. A value is not truncated: every character stays visible, because the end of a glob is the part that names what is trusted.

#### Scenario: A long value wraps at the cap

- **GIVEN** an exclusion whose value is a path glob with no spaces, longer than the cap
- **WHEN** the detection tuning view renders the exclusion table at a 1280px-wide viewport
- **THEN** the value is laid out at the cap width and spans more than one line
- **AND** the table does not scroll horizontally
