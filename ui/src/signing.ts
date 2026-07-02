import type { CodeSigning } from "./types";

// CS_ADHOC is the kernel code-signing status bit for an ad-hoc signature (CS_ADHOC in <kern/cs_blobs.h>), carried verbatim in the
// wire's code_signing.flags. It is the only CS_* bit the UI interprets; the rest of the bitmask passes through untouched.
export const CS_ADHOC = 0x2;

// SigningVerdictKind is the closed set of signer categories the UI derives (issue #580). On macOS the signer category is the honest
// conviction evidence: ESF exposes signing flags and identifiers, not a notarization ticket check.
export type SigningVerdictKind = "unsigned" | "ad-hoc" | "developer-id" | "platform" | "signed";

export interface SigningVerdict {
  kind: SigningVerdictKind;
  // label is the operator-facing wording shared by the node tooltip and the detail panel badge.
  label: string;
}

// deriveSigningVerdict maps a process's code-signing fields to its signer category. Decision order matters. No block at all means
// unsigned: the extension omits code_signing when both identifiers are absent. The ad-hoc flag then wins over everything else the
// block claims, since an ad-hoc signature carries no verifiable identity. A non-empty team id means Developer ID, checked BEFORE the
// platform flag because ESF redaction on ad-hoc dev builds reports is_platform_binary=true for every process (issue #187) while a
// team id is only ever present when the signature carries one. The platform flag then identifies Apple platform binaries (signing
// identity, no team id), and the residual (an identity with none of the above) reads "signed".
export function deriveSigningVerdict(cs: CodeSigning | undefined): SigningVerdict {
  if (!cs) return { kind: "unsigned", label: "unsigned" };
  if ((cs.flags & CS_ADHOC) !== 0) return { kind: "ad-hoc", label: "ad-hoc signature" };
  if (cs.team_id) return { kind: "developer-id", label: `Developer ID (Team ${cs.team_id})` };
  if (cs.is_platform_binary) return { kind: "platform", label: "Apple platform" };
  return { kind: "signed", label: "signed" };
}

// isEvidenceMarked reports whether a verdict warrants the graph's amber evidence marker: the two categories that carry no
// verifiable identity, which is the triage cue an analyst scans for.
export function isEvidenceMarked(verdict: SigningVerdict): boolean {
  return verdict.kind === "unsigned" || verdict.kind === "ad-hoc";
}
