import type { CodeSigning } from "./types";

// The two kernel code-signing status bits the UI interprets (CS_VALID / CS_ADHOC in <kern/cs_blobs.h>), carried verbatim in the
// wire's code_signing.flags; the rest of the bitmask passes through untouched. CS_VALID is the kernel's "this signature is still
// dynamically valid" bit: every process that passed AMFI at exec has it, and it is cleared when the signature is later invalidated
// (self-modification, injection), which Endpoint Security can report with the identifiers still populated.
export const CS_VALID = 0x1;
export const CS_ADHOC = 0x2;

// SigningVerdictKind is the closed set of signer categories the UI derives (issue #580). On macOS the signer category is the honest
// conviction evidence: ESF exposes signing flags and identifiers, not a notarization ticket check.
export type SigningVerdictKind = "unsigned" | "invalid" | "ad-hoc" | "developer-id" | "platform" | "signed";

export interface SigningVerdict {
  kind: SigningVerdictKind;
  // label is the operator-facing wording shared by the node tooltip and the detail panel badge.
  label: string;
}

// deriveSigningVerdict maps a process's code-signing fields to its signer category. Decision order matters. No block at all means
// unsigned: the extension omits code_signing when both identifiers are absent. A cleared CS_VALID bit then wins over whatever the
// block claims: the identifiers name who signed the binary, but the kernel no longer vouches for the signature (tampered or
// invalidated). The ad-hoc flag comes next, since an ad-hoc signature carries no verifiable identity. A non-empty team id means
// Developer ID, checked BEFORE the platform flag because ESF redaction on ad-hoc dev builds reports is_platform_binary=true for
// every process (issue #187) while a team id is only ever present when the signature carries one. The platform flag then identifies
// Apple platform binaries, and the residual keeps requiring an identity: a block with empty identifiers reads unsigned, not signed.
export function deriveSigningVerdict(cs: CodeSigning | undefined): SigningVerdict {
  if (!cs) return { kind: "unsigned", label: "unsigned" };
  if ((cs.flags & CS_VALID) === 0) return { kind: "invalid", label: "invalid signature" };
  if ((cs.flags & CS_ADHOC) !== 0) return { kind: "ad-hoc", label: "ad-hoc signature" };
  if (cs.team_id) return { kind: "developer-id", label: `Developer ID (Team ${cs.team_id})` };
  if (cs.is_platform_binary) return { kind: "platform", label: "Apple platform" };
  if (cs.signing_id) return { kind: "signed", label: "signed" };
  return { kind: "unsigned", label: "unsigned" };
}

// isEvidenceMarked reports whether a verdict warrants the graph's amber evidence marker: the categories that carry no identity the
// kernel still vouches for, which is the triage cue an analyst scans for.
export function isEvidenceMarked(verdict: SigningVerdict): boolean {
  return verdict.kind === "unsigned" || verdict.kind === "ad-hoc" || verdict.kind === "invalid";
}
