# web-ui

## ADDED Requirements

### Requirement: The detection tuning Cost column reports the total cost

The detection tuning table's Cost column SHALL report the total wall time a rule's evaluations consumed over the window as its leading figure, and SHALL keep the mean per attempt as a secondary figure beside it. Sorting the column SHALL order by that total.

A mean alone does not answer which rule is worth tuning, because it carries no volume: a rule evaluated once at 4ms outranks a rule evaluated twenty-four times at 2.5ms, having cost a fourteenth as much. The total is the figure an operator is deciding against, and the mean stays because it separates a rule that is expensive on every attempt from one with a single bad batch.

The total SHALL be summed from the same stored per-day durations the mean is derived from, rather than reconstructed by multiplying the mean by the attempt count. The mean is an integer division, so the product drifts from the real total by up to one nanosecond per attempt, and the drift grows with exactly the attempt counts that make a rule worth looking at.

The worst case SHALL remain reachable from the cell without being its leading figure, and the undecided count SHALL continue to be shown only when it is not zero. The column's explanatory note SHALL name which figure is the total and which is the mean, since two durations in one cell are otherwise ambiguous.

#### Scenario: The cell leads with the total and keeps the mean

- **GIVEN** a rule evaluated 24 times over the window, averaging 2.5ms per attempt
- **WHEN** an operator opens the detection tuning view
- **THEN** the rule's Cost cell shows the total for the window as its leading figure
- **AND** it shows the mean per attempt as a secondary figure
- **AND** the worst single evaluation is reachable from the cell without being its leading figure

#### Scenario: Sorting by cost ranks by total rather than by mean

- **GIVEN** one rule evaluated once at a high mean and another evaluated many times at a lower mean, the second having consumed more time in total
- **WHEN** an operator sorts the table by Cost
- **THEN** the rule that consumed more time in total is ranked first

#### Scenario: The total is exact rather than derived from the rounded mean

- **GIVEN** a rule whose stored per-day durations do not divide evenly by its attempt count
- **WHEN** the Cost column reports its total for the window
- **THEN** the total equals the sum of the stored per-day durations
- **AND** it is not the product of the reported mean and the attempt count

### Requirement: The detection tuning view presents the most recent load

The detection configuration view SHALL present the results of its most recent load, and SHALL discard the results of an earlier load that completes after it.

Loads overlap in practice: a mode or severity change reloads the view while an earlier load may still be in flight. An earlier response arriving later would otherwise replace newer data with older, with no error and nothing on screen to indicate it, leaving an operator reading a table that disagrees with the change they just made.

Being mounted is not the same question as being current, so a guard that only asks whether the view is still alive does not answer this: both responses pass it, and the slower one wins whichever was started first.

#### Scenario: An earlier load completing later does not replace newer data

- **GIVEN** two loads of the detection configuration view in flight, the earlier one returning different data from the later
- **WHEN** the earlier load completes after the later one has already been presented
- **THEN** the view still presents the later load's data
- **AND** the earlier load's data is not presented
