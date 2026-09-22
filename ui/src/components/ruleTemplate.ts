// The starting document for a new rule, and the one thing a caller may seed into it.
//
// Its own module rather than living beside the editor component: the editor's file exports a component, and a module that exports
// both a component and a helper cannot be fast-refreshed. The tests exercise the helper directly, which is the other reason.

// A new rule starts from the smallest document the loader accepts, so the operator edits a rule rather than recalling the format.
export const NEW_RULE_TEMPLATE = `title: My rule
status: experimental
description: What this rule detects.
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image: '/usr/bin/example'
    condition: selection
level: medium
`;

const TECHNIQUE_BASE = /^T\d{4}$/;
const TECHNIQUE_SUB = /^\d{3}$/;

// isAttackTechnique reports whether a string is an ATT&CK technique id: T1059, or T1059.004 with exactly one sub-technique part.
//
// Split and matched in two rather than as one pattern with an optional group, which reads as a nested quantifier to the unsafe
// regex rule. Two anchored patterns with fixed counts cannot backtrack at all, which is the property that rule is protecting.
export function isAttackTechnique(value: string): boolean {
  const parts = value.split(".");
  if (parts.length > 2) return false;
  if (!TECHNIQUE_BASE.test(parts[0])) return false;
  return parts.length === 1 || TECHNIQUE_SUB.test(parts[1]);
}

// seedTechnique puts the technique the operator came to cover into the starting document, in Sigma's tag vocabulary: lowercase,
// dot-separated, `attack.` prefixed, so T1059.004 becomes attack.t1059.004. Coverage sends the id when the reader followed a gap,
// and answering that gap is the point of the trip; making them retype the id they just clicked is how the loop gets broken.
//
// The id is validated first. It arrives from the query string, which anyone can write, and this text is put into a document the
// rule loader parses, so only ATT&CK's own shape reaches the template.
export function seedTechnique(template: string, technique: string | null): string {
  if (technique === null || !isAttackTechnique(technique)) return template;
  return `${template}tags:\n    - attack.${technique.toLowerCase()}\n`;
}
