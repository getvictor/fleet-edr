// Package appcontrol is the rules-context subdomain for the
// Application Control subsystem. It owns the durable representation
// of policies and rules (the `app_control_policies` +
// `app_control_rules` tables), the per-rule_type identifier
// validators, and the lookup paths the REST handler and the agent
// fan-out consume.
//
// The demo cut enforces only the BINARY rule type; the validator
// returns ErrAppControlUnsupportedRuleType for every other value on
// the rule_type enum so the REST surface can reject those types with
// a stable typed error. The remaining types come online one at a
// time as their decision-engine branches and ESF-side identifier
// extractors land in the extension.
package appcontrol
