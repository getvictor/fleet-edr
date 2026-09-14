# Web UI delta

## ADDED Requirements

### Requirement: Rule forms require an enforcement choice

The application-control Add rule and Paste many dialogs SHALL ask for the rule's enforcement, Detect or Protect, and SHALL describe what each does: Detect lets the executable run and records each match, and Protect blocks it. Neither SHALL be preselected, and saving SHALL stay disabled until one is chosen, because the server requires it and either choice made by default is wrong for someone. Reopening a dialog SHALL clear the choice. A saved rule SHALL carry the enforcement chosen, applied to every row of a paste.

#### Scenario: Neither enforcement is preselected

- **GIVEN** an operator opening the Add rule dialog with a valid identifier and a reason entered
- **WHEN** no enforcement has been chosen
- **THEN** neither Detect nor Protect is selected and saving is disabled
- **AND** choosing one enables saving and the saved rule carries it
- **AND** reopening the dialog clears the choice

#### Scenario: A paste applies the chosen enforcement to every row

- **GIVEN** an operator previewing a paste of several identifiers with a reason entered
- **WHEN** they choose Detect and save
- **THEN** every rule in the bulk upsert carries `enforcement=DETECT`
