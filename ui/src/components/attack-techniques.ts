// Static catalog of MITRE ATT&CK technique metadata for the techniques the
// shipped detection rules cover. We don't ship the full ATT&CK enterprise
// matrix (~600 techniques) into the UI bundle — that's what the upstream
// Navigator exists for. This catalog is just the techniques we trigger on
// today, with their human-readable name and tactic.
//
// When a rule starts covering a new technique, add the entry here. Missing
// entries fall back to "Unmapped" in the AttackCoverage view, which is a
// loud-but-not-broken hint that this file needs an update.

export interface TechniqueMeta {
  id: string;
  name: string;
  // ATT&CK has 14 enterprise tactics. We label with the human-readable name
  // (matching attack.mitre.org URLs) so the UI doesn't need a tactic-id
  // lookup.
  tactic: string;
}

export const TECHNIQUE_CATALOG: Record<string, TechniqueMeta> = {
  "T1059": {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
  },
  "T1059.002": {
    id: "T1059.002",
    name: "AppleScript",
    tactic: "Execution",
  },
  "T1059.004": {
    id: "T1059.004",
    name: "Unix Shell",
    tactic: "Execution",
  },
  "T1105": {
    id: "T1105",
    name: "Ingress Tool Transfer",
    tactic: "Command and Control",
  },
  "T1543.001": {
    id: "T1543.001",
    name: "Launch Agent",
    tactic: "Persistence",
  },
  "T1543.004": {
    id: "T1543.004",
    name: "Launch Daemon",
    tactic: "Persistence",
  },
  "T1548.003": {
    id: "T1548.003",
    name: "Sudo and Sudo Caching",
    tactic: "Privilege Escalation",
  },
  "T1555.001": {
    id: "T1555.001",
    name: "Keychain",
    tactic: "Credential Access",
  },
  "T1566.001": {
    id: "T1566.001",
    name: "Spearphishing Attachment",
    tactic: "Initial Access",
  },
  "T1574.006": {
    id: "T1574.006",
    name: "Dynamic Linker Hijacking",
    tactic: "Defense Evasion",
  },
};
