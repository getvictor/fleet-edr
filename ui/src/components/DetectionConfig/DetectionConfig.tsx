import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  listDetectionExclusions,
  listDetectionRuleSettings,
  listDetectionRuleEvalStats,
  listDetectionRuleMatchCounts,
  createDetectionExclusion,
  deleteDetectionExclusion,
  upsertDetectionRuleSetting,
  fetchRuleDocs,
  DetectionConfigApiError,
  type DetectionExclusion,
  type DetectionRuleSetting,
  type RuleEvalSummary,
  type RuleMatchCount,
  type RuleDocEntry,
} from "../../api";
import { useCan, PermissionAction } from "../../permissions-core";
import { formatRelativeISO } from "../../time";
import { PageHeader } from "../ui/PageHeader";
import { Table, EmptyState } from "../ui/Table";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Input";
import { ReasonModal } from "./ReasonModal";
import "./DetectionConfig.scss";

// The canonical display order for exclusion match types, mirroring api.ExclusionMatchType server-side. The editor never offers all of
// these at once: it filters this list down to the match types the selected rule actually consults (issue #520), sourced from that
// rule's supported_exclusion_match_types on GET /api/rules.
const MATCH_TYPES = ["path_glob", "parent_path_glob", "team_id", "signing_id", "cdhash", "sha256", "command_substring", "domain"] as const;

// The per-rule modes an operator can select. Monitor was excluded here by the detection-tuning-author-and-modes change, on the
// grounds that it had no review surface and was a legacy value on a handful of rows.
//
// Issue #764 overturned both halves of that. Sixty-six imported rules now DEFAULT to monitor, so it is the mode most of the catalog
// runs in rather than a legacy value, and the surface that reviews them is the point of the mode. Leaving it unselectable made
// promotion a one-way door: modeOptions renders monitor for a rule sitting in it, so such a rule could be promoted to alert, and
// then nothing could put it back. An operator who promotes a noisy rule and wants to undo that is exactly the case monitor exists
// for, and it was the one case the control could not express.
//
// Order is alert, monitor, disabled: increasing restriction, which is the order the modes are explained in everywhere else.
const MODES = ["alert", "monitor", "disabled"] as const;

// modeReach ranks the modes by how much a rule does in them: alert raises, monitor records, disabled produces nothing. The rank
// decides whether a change needs an operator's reason. Reducing what a rule does is a decision someone should justify in the audit
// trail; restoring it is not, which is the principle the surface already applied to alert-versus-disabled and which now has to hold
// for the four transitions monitor adds.
//
// A mode this build does not recognise ranks as alert, so a stored value we cannot read is treated as the most capable state and
// moving away from it still asks for a reason.
function modeReach(mode: string): number {
  switch (mode) {
    case "disabled":
      return 0;
    case "monitor":
      return 1;
    default:
      return 2;
  }
}

// reducesReach reports whether moving from priorMode to mode makes the rule do less.
function reducesReach(priorMode: string, mode: string): boolean {
  return modeReach(mode) < modeReach(priorMode);
}

// ReducingMode is the set of modes a rule can be moved INTO that make it do less, which is exactly the set that opens the reason
// modal. Typing it means MODE_PROMPT below cannot be missing an entry, so the modal needs no fallback copy for a mode that cannot
// reach it.
type ReducingMode = "monitor" | "disabled";

function isReducingMode(mode: string): mode is ReducingMode {
  return mode === "monitor" || mode === "disabled";
}

// generatedReason names the transition for a change that does not prompt. Written per transition rather than interpolated, because
// these strings are read in the audit log by someone reconstructing what happened, and "promoted from monitor to alert" says more
// than a mechanical restatement of two enum values.
//
// The prior mode is only named when it is one this build recognises. modeOptions deliberately renders a stored mode we cannot read,
// so an operator can move a rule off it, and reaching that path from an unrecognised value used to record "re-enabled" for a rule
// that was never disabled. A neutral phrasing is worth more in an audit log than a confident wrong one.
function generatedReason(priorMode: string, mode: string): string {
  switch (priorMode) {
    case "monitor":
      return mode === "alert" ? "promoted from monitor to alert via admin UI" : `mode changed from monitor to ${mode} via admin UI`;
    case "disabled":
      return mode === "alert" ? "re-enabled via admin UI" : "re-enabled in monitor mode via admin UI";
    case "alert":
      return `mode changed from alert to ${mode} via admin UI`;
    default:
      return `mode changed to ${mode} via admin UI`;
  }
}

// MODE_PROMPT is the reason-modal copy per reducing target. The modal previously hard-coded the disable wording, which was correct
// while disabled was the only reducing choice: offering monitor without this would have shown an operator a "Disable rule" button
// for a change that disables nothing.
const MODE_PROMPT: Record<ReducingMode, { verb: string; confirmLabel: string; description: string }> = {
  disabled: {
    verb: "Disable",
    confirmLabel: "Disable rule",
    // Target-state wording, because this copy is also shown for monitor -> disabled. "Stops producing alerts" was accurate only
    // from alert: a monitor rule produces none already, and what it actually loses is the recorded signal an operator would use to
    // decide whether to promote it.
    description:
      "The rule stays registered but stops evaluating: it will produce neither alerts nor monitor signals. " +
      "This is recorded in the audit log.",
  },
  monitor: {
    verb: "Move to monitor",
    confirmLabel: "Move to monitor",
    description:
      "The rule keeps evaluating and records what it would have fired on, but stops raising alerts. This is recorded in the audit log.",
  },
};

// modeOptions returns the modes shown for a row. It prepends the row's current mode when that mode is not one of MODES, so the
// controlled <select> renders a matching option instead of silently displaying the first one. Every mode the server defines is now
// selectable, so this only fires on a stored value this build does not recognise, where showing the operator what is actually
// persisted beats showing them something else.
function modeOptions(current: string): readonly string[] {
  return (MODES as readonly string[]).includes(current) ? MODES : [current, ...MODES];
}

// Severity-override choices; the empty value means "no override" (keep the rule's declared severity).
const SEVERITIES = ["", "low", "medium", "high", "critical"] as const;

// Header tooltip for the Mode column. Held here rather than inline because the sentence has to carry the per-rule default, and
// as a JSX attribute it was a single 248-character source line.
const MODE_COLUMN_TOOLTIP =
  "Alert raises alerts; monitor evaluates and records a signal instead; disabled emits nothing. " +
  "A rule with no setting here runs in its own default, which is alert for the rules Fleet wrote and monitor for imported ones.";

// Shown in place of the column's normal caption when the counts read failed, so the missing evidence is stated rather than left
// for the reader to infer from a column that says nothing was recorded.
// The notes say what the mean is over, because "1.2ms" beside a promote control invites being read as the cost of one
// alert rather than of one run, and they point at the HOVER for the worst case because that is where renderCost puts it:
// an earlier wording promised it "in each cell", which the cell never showed.
//
// Each note opens with its column's name, which is bolded where it renders. Unbolded, "Observed is what each rule
// matched" reads as a sentence missing its subject until you notice the first word is a column header.
//
// The body is held separately from the name so the same sentence can be a `title` attribute, which cannot take markup,
// without a second copy of the prose to drift out of step with the visible one.
function observedNoteBody(days: number): string {
  return (
    `counts how often each rule matched while in monitor mode, over the last ${String(days)} days. It shows how noisy a ` +
    "rule is, not how many alerts you would get by promoting it: once a rule alerts, repeated matches on the same " +
    "process become one alert."
  );
}

// Deliberately plainer than it was. An earlier version described the cell's layout ("leads with ... carries behind it")
// and called the figure "the server's bill for the rule, not the work it completed", which is a riddle rather than an
// explanation. What an operator needs is what the numbers are, which one the sort uses, and why that is the right one.
function costNoteBody(days: number): string {
  return (
    `is how much server time each rule used over the last ${String(days)} days: the total first, then the average per ` +
    "run. Hover a cell for the slowest single run. Sorting ranks by the total, because a cheap rule that runs constantly " +
    "can cost more than an expensive one that rarely runs. Retries count as runs, so this is time spent rather than work " +
    "completed, and a run that ends without deciding is counted too and shown as undecided."
  );
}

const costColumnTooltip = (days: number): string => `Cost ${costNoteBody(days)}`;

const OBSERVED_UNAVAILABLE_TOOLTIP =
  "Match counts could not be loaded, so this column shows no evidence either way. Reload before reading a rule as quiet.";

// formatMatches keeps large counts readable at a glance, since the difference that matters when scanning this column is between
// tens and thousands rather than between 4,102 and 4,140.
const matchesAbbreviationFloor = 10_000;

function formatMatches(n: number): string {
  if (n >= matchesAbbreviationFloor) return `${String(Math.round(n / 1000))}k`;
  return n.toLocaleString();
}

// renderObserved draws the Observed cell for one rule.
//
// Three states, deliberately distinct. A failed read reads UNAVAILABLE, not "not recorded": the spec requires a read failure be reported as
// an error rather than as an empty result, because an empty result reads as a quiet rule and a quiet rule is what gets promoted.
// Rendering a failure as absence would invert the meaning of the column at exactly the moment it is least reliable.
//
// A rule with nothing recorded reads "not recorded" rather than "0". Zero is a claim that the rule was watched and did nothing;
// absence can equally mean it was promoted before the window opened, or that the window predates its registration. Spelled out
// rather than drawn as a dash glyph, both because the repo forbids the character in user-facing text and because the words say
// the distinction the glyph only implies.
// AbbreviatedFigure is the disclosure both abbreviated columns use, so the pair cannot diverge (#902).
//
// The columns draw "42k" and "1.5ms" deliberately: at a thousand rules they have to stay scannable. The precise figures used to
// live in a native `title`, which opens on POINTER HOVER ONLY. A sighted keyboard user and anyone on a touch device could not
// reach them at all, and these are the numbers the columns exist for: the Cost column's whole purpose is finding the slow rule,
// and "usually fast, occasionally terrible" is an answer that lives entirely in the worst-case figure.
//
// A button rather than a focusable span, because this does something when activated; keyboard activation and tap then come from
// the platform rather than from hand-rolled key handlers.
//
// The full sentence is ALWAYS in the DOM, visually hidden until expanded rather than absent. That is what keeps assistive
// technology whole: it reads the description through aria-describedby whether or not a sighted user has expanded anything, which
// is exactly what the old aria-label gave it. Rendering it only when open would quietly take that away in the name of fixing
// access for everyone else. `title` stays for pointer users, so no one loses the hover they have now.
function AbbreviatedFigure({ full, children }: { full: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <span className="detection-config__figure">
      <button
        type="button"
        className="detection-config__figure-toggle"
        aria-expanded={open}
        aria-describedby={id}
        title={full}
        onClick={() => {
          setOpen((wasOpen) => !wasOpen);
        }}
      >
        {children}
      </button>
      <span id={id} className={open ? "detection-config__figure-full" : "detection-config__sr-only"}>
        {full}
      </span>
    </span>
  );
}

function renderObserved(count: RuleMatchCount | undefined, ruleID: string, days: number, unavailable: boolean) {
  if (unavailable) {
    return (
      <span className="detection-config__observed-unavailable" aria-label={`match counts unavailable for ${ruleID}`}>
        unavailable
      </span>
    );
  }
  if (count === undefined) {
    return (
      <span className="detection-config__observed-none" aria-label={`no matches recorded for ${ruleID}`}>
        not recorded
      </span>
    );
  }
  const hosts = `${String(count.hosts)} host${count.hosts === 1 ? "" : "s"}`;
  // Recency is the third signal the column carries: a rule that matched heavily and has since gone quiet is a different promotion
  // case from one still matching. Phrased by the shared helper rather than a local one, so this reads like the Hosts list instead
  // of inventing a second vocabulary for the same idea.
  const lastSeen = formatRelativeISO(count.last_seen);
  const matches = `${count.matches.toLocaleString()} match${count.matches === 1 ? "" : "es"}`;
  const title =
    `approximately ${matches} on ${hosts} in the last ${String(days)} days` + (lastSeen === "" ? "" : `, last matched ${lastSeen}`);
  return (
    <AbbreviatedFigure full={title}>
      {formatMatches(count.matches)}
      <span className="detection-config__observed-hosts"> on {hosts}</span>
      {lastSeen === "" ? null : <span className="detection-config__observed-last"> &middot; {lastSeen}</span>}
    </AbbreviatedFigure>
  );
}

// COST_UNAVAILABLE_TOOLTIP is the Cost column's version of OBSERVED_UNAVAILABLE_TOOLTIP, and it exists separately because the two
// reads fail independently: one column can be evidence while the other is silence, and a shared sentence would claim both are.
const COST_UNAVAILABLE_TOOLTIP =
  "Evaluation statistics could not be loaded, so this column shows no evidence either way. Reload before reading a rule as cheap.";

// formatDuration renders a nanosecond figure at the scale a reader is comparing at.
//
// Sub-millisecond timings are the normal case and the interesting ones are the outliers, so the unit changes rather than the
// precision: nanoseconds below a microsecond, microseconds below a millisecond, milliseconds below a second, seconds above.
//
// One decimal on every unit except nanoseconds, which are whole. The question this column answers is "which rule is slow", not
// "how slow exactly", and trailing digits make a scan harder; at nanosecond scale a decimal would be false precision on a figure
// that is already an integer division of a sum by a count.
const nsPerUs = 1_000;
const nsPerMs = 1_000_000;
const nsPerSecond = 1_000_000_000;

function formatDuration(ns: number): string {
  // Nanoseconds below a microsecond, because `(49 / 1000).toFixed(1)` is "0.0" and a rule that measured 49ns would read as one
  // that measured nothing. The column's own test asserts a measured zero outranks an absent one, so the two must stay
  // distinguishable in the display as well as in the sort.
  if (ns < nsPerUs) return `${String(ns)}ns`;
  if (ns < nsPerMs) return `${(ns / nsPerUs).toFixed(1)}us`;
  if (ns < nsPerSecond) return `${(ns / nsPerMs).toFixed(1)}ms`;
  return `${(ns / nsPerSecond).toFixed(1)}s`;
}

// renderCost draws the Cost cell for one rule: what its evaluations have cost, and how often they could not decide.
//
// Three states, mirroring renderObserved for the same reason it has them. A failed read reads UNAVAILABLE rather than "not
// recorded", because an empty result reads as a cheap rule, and a cheap-looking rule is exactly what an operator hunting a slow
// one will skip over.
//
// The MEAN is displayed and the maximum rides in the tooltip, rather than the other way round. Scanning a column of maxima finds
// the rule with one bad batch; scanning a column of means finds the rule that is expensive every time, which is the one holding up
// the drain loop. The maximum still has to be reachable, because a rule that is usually fast and occasionally terrible is a real
// answer, so it is in the label rather than dropped.
//
// Retryable misses are shown only when there are any. A "0 misses" annotation on every row would cost the column's width for the
// rows where it says nothing, and the count matters precisely when it is not zero.
function renderCost(stat: RuleEvalSummary | undefined, ruleID: string, days: number, unavailable: boolean) {
  if (unavailable) {
    return (
      <span className="detection-config__observed-unavailable" aria-label={`evaluation statistics unavailable for ${ruleID}`}>
        unavailable
      </span>
    );
  }
  if (stat === undefined) {
    return (
      <span className="detection-config__observed-none" aria-label={`no evaluations recorded for ${ruleID}`}>
        not recorded
      </span>
    );
  }
  const evaluations = `${stat.evaluations.toLocaleString()} evaluation${stat.evaluations === 1 ? "" : "s"}`;
  // "could not decide", not "were retried", and the difference is real rather than pedantic: the counter increments the moment an
  // attempt returns a retryable outcome, before anything knows whether another attempt follows. A batch that is eventually set
  // aside has its last miss counted with no retry after it, so labelling the figure as completed retries overstates it for exactly
  // the rules an operator is chasing.
  // Always in the LABEL, even at zero, because that is where the figure is promised and where a reader without the column's width
  // gets it. Only the VISIBLE annotation is suppressed at zero, since "0 undecided" on every row spends width saying nothing.
  const misses = `, ${stat.retryable_misses.toLocaleString()} of which could not decide`;
  const title =
    `${formatDuration(stat.total_eval_ns)} in total across ${evaluations} in the last ${String(days)} days, ` +
    `${formatDuration(stat.mean_eval_ns)} on average and ${formatDuration(stat.max_eval_ns)} at worst${misses}`;
  return (
    <AbbreviatedFigure full={title}>
      {formatDuration(stat.total_eval_ns)}
      <span className="detection-config__observed-hosts"> total</span>
      <span className="detection-config__observed-hosts"> &middot; {formatDuration(stat.mean_eval_ns)} avg</span>
      {stat.retryable_misses === 0 ? null : (
        <span className="detection-config__observed-last"> &middot; {stat.retryable_misses.toLocaleString()} undecided</span>
      )}
    </AbbreviatedFigure>
  );
}

// SEVERITY_ORDER lists declared severities most- to least-severe; the rule-modes table sorts by it (ascending rank = critical first).
const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

// severityRank returns a rule's position in SEVERITY_ORDER (0 = critical). A severity that isn't one of the four (an unset "" or an
// unrecognized value) ranks last, so "(unspecified)" rules fall to the bottom of the table.
function severityRank(sev: string): number {
  const i = SEVERITY_ORDER.indexOf(sev as (typeof SEVERITY_ORDER)[number]);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

// errMessage renders a typed detection-config API error's message, falling back to a generic string.
function errMessage(err: unknown): string {
  if (err instanceof DetectionConfigApiError) return err.message;
  return err instanceof Error ? err.message : "Unknown error";
}

// globalSetting picks the global-scope (host_group_id 0) setting for a rule, the only scope the Phase A surface edits.
function globalSetting(settings: DetectionRuleSetting[], ruleID: string): DetectionRuleSetting | undefined {
  return settings.find((s) => s.rule_id === ruleID && s.host_group_id === 0);
}

// DetectionConfig is the admin surface for detection-rule tuning (issue #459): per-host false-positive exclusions and per-rule
// mode/severity. It edits global scope only (host-group scoping arrives with editable host groups). Write affordances are gated on
// detection_config.write; the server still enforces. The per-rule "settings" are mode + severity today; when a rule declares
// additional config the table grows generically.
export function DetectionConfig() {
  const can = useCan();
  const canWrite = can(PermissionAction.DetectionConfigWrite);

  const [exclusions, setExclusions] = useState<DetectionExclusion[]>([]);
  const [rules, setRules] = useState<RuleDocEntry[]>([]);
  const [settings, setSettings] = useState<DetectionRuleSetting[]>([]);
  // Keyed by rule id, holding only rules that matched: a rule absent here has nothing recorded, which the table spells out as
  // "not recorded" rather than showing a zero (see the cell).
  // Possibly-undefined per key on purpose: a rule with nothing recorded is ABSENT from the response rather than present with a
  // zero, so the lookup genuinely can miss and the guard below is a real one rather than a formality.
  const [observed, setObserved] = useState<Record<string, RuleMatchCount | undefined>>({});
  const [observedDays, setObservedDays] = useState<number>(0);
  // observedUnavailable records that the counts read FAILED, which is a different claim from "no rule matched". Without it every
  // cell would read "not recorded", i.e. as evidence that every rule is quiet, which is the reading that gets a noisy rule
  // promoted; with it they read "unavailable" instead.
  const [observedUnavailable, setObservedUnavailable] = useState(false);
  // The Cost column's own three, kept separate from the Observed ones rather than merged: the two reads are separate requests that
  // fail separately, and one shared "unavailable" flag would blank a column that loaded fine.
  const [cost, setCost] = useState<Record<string, RuleEvalSummary | undefined>>({});
  const [costDays, setCostDays] = useState<number>(0);
  const [costUnavailable, setCostUnavailable] = useState(false);
  // Off by default, so the table's usual reading order (most severe first) is what an operator sees when they came here to tune a
  // rule they already have in mind. Sorting by cost answers the other question, which is which rule to look at at all.
  const [sortByCost, setSortByCost] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  // mutating serializes write actions: while a create/delete/upsert is in flight (and its reload settles) the form controls and
  // row buttons disable, so a double-click can't double-submit and a second rule-mode change can't race a stale peer field in.
  const [mutating, setMutating] = useState(false);
  // mountedRef gates the state setters in reload() so a response landing after unmount doesn't set state on a dead component.
  //
  // Set true on EVERY run, not just at useRef's initial value. StrictMode runs an effect, its cleanup, then the effect again on
  // the same instance, so a cleanup-only version latches false on first mount and every later reload() returns before its
  // setters. The page then renders its headings and an empty table with no error, since nothing failed: the reads all return
  // 200 and their results are dropped. Production never double-invokes, so this is invisible outside dev, which is exactly what
  // makes it expensive: it presents as "the dev proxy is broken" and sends you looking at the network tab.
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);
  // reloadSeqRef makes the LATEST reload the one whose results are applied. mountedRef cannot do this on its own: it answers
  // "is this component alive", not "is this response still the current one", so two overlapping reloads both write and the
  // SLOWER one wins whichever order they were started in. Two reach that state: StrictMode's double-invoke starts one per
  // effect run, and a mode or severity mutation reloads while an earlier reload may still be in flight.
  const reloadSeqRef = useRef(0);

  // Add-exclusion form state. formExpires is an optional YYYY-MM-DD from a date input; converted to an RFC3339 end-of-day instant.
  const [formRuleID, setFormRuleID] = useState("");
  // Empty until a rule is selected: the match-type picker is populated from the chosen rule's supported set (issue #520).
  const [formMatchType, setFormMatchType] = useState<string>("");
  const [formValue, setFormValue] = useState("");
  const [formReason, setFormReason] = useState("");
  const [formExpires, setFormExpires] = useState("");

  // pendingMode holds a not-yet-applied disable (the alerting-reducing change) while the reason modal collects an operator
  // justification. modalError surfaces a failed confirm inside the modal so it stays open for a retry.
  const [pendingMode, setPendingMode] = useState<{ ruleID: string; ruleTitle: string; mode: ReducingMode; severity: string } | null>(null);
  const [modalError, setModalError] = useState<string | null>(null);

  // The exclusion picker lists rules alphabetically by their canonical title so an operator can scan to the rule they want. Titles
  // are clean single names (issue #519), so the option shows the title verbatim.
  const rulesByName = useMemo(() => [...rules].sort((a, b) => a.doc.title.localeCompare(b.doc.title)), [rules]);
  // supportedMatchTypesFor returns the match types the given rule consults (issue #520), in canonical display order. The exclusion
  // editor offers only these, so an operator cannot store a (rule, match type) pair the rule ignores. A rule with no supported types
  // (or an unknown id) yields an empty list, which disables the match-type picker. The server is the source of truth: any supported
  // value not in the UI's canonical MATCH_TYPES order (e.g. a match type a newer server added while this bundle is version-skewed) is
  // still offered, appended after the known ones, so the editor stays functional across a rolling deploy rather than silently hiding it.
  const supportedMatchTypesFor = useCallback(
    (ruleID: string): string[] => {
      const supported = rules.find((r) => r.id === ruleID)?.supported_exclusion_match_types ?? [];
      const known = MATCH_TYPES.filter((m) => supported.includes(m));
      const unknown = supported.filter((m) => !(MATCH_TYPES as readonly string[]).includes(m));
      return [...known, ...unknown];
    },
    [rules],
  );
  const supportedMatchTypes = useMemo(() => supportedMatchTypesFor(formRuleID), [supportedMatchTypesFor, formRuleID]);

  // The rule-modes table orders by declared severity (critical first), where muting a rule is most consequential, then
  // alphabetically by title within a severity band.
  const rulesBySeverity = useMemo(
    () => [...rules].sort((a, b) => severityRank(a.doc.severity) - severityRank(b.doc.severity) || a.doc.title.localeCompare(b.doc.title)),
    [rules],
  );

  // The order the table is actually drawn in. Sorting by cost is what makes the Cost column answer "which rule should I look at",
  // rather than only "what does this rule cost": without it the slowest rule sits wherever its severity puts it, which is findable
  // in thirteen rows and not in a thousand. The server already returns the statistics in this order, and keying them by rule id to
  // render them beside their rule is what discards it, so this restores an ordering rather than inventing one.
  //
  // A rule with NO statistics sorts last rather than as zero, for the same reason its cell reads "not recorded": absence is not a
  // measurement of nothing, and sorting them up as zero-cost would bury the answer under every rule that never ran.
  // sortActive, not sortByCost, everywhere the order is produced OR described. With no statistics there is nothing to sort by, so
  // a sort that stays "on" announces an order it is not producing: the rows come out in severity order while the header says
  // slowest first. Clearing the data was not enough on its own; the CLAIM had to go with it.
  //
  // An EMPTY result counts as nothing to sort by too, and it is a different state from a failed read: the response was fine, no
  // rule has evaluated in the window yet. A fresh deployment is exactly that. Without this the sort switches on over a table where
  // every comparison is a tie, so the rows keep severity order while the header announces slowest first, which is the same untrue
  // claim by a route that does not involve an outage.
  // Defined on what is RENDERED, not on what the response contained, and the difference is a real state rather than a nicety.
  // Statistics outlive the rule they describe: a rule content reload can retire a rule while its rows sit in the table until
  // retention expires, so a response can be non-empty and still leave every visible row without a figure. Sorting would then be
  // enabled over a table of ties again.
  //
  // Defining it this way is also what makes the condition general rather than a list of failure modes. I claimed that once while
  // it was still derived from the response, and review found this case; derived from the intersection, "there is something on
  // screen to sort by" is the whole question and a sixth route to having nothing cannot need a sixth branch.
  const haveCost = useMemo(() => rulesBySeverity.some((r) => cost[r.id] !== undefined), [rulesBySeverity, cost]);
  const sortActive = sortByCost && haveCost;

  const rulesForTable = useMemo(() => {
    if (!sortActive) return rulesBySeverity;
    return [...rulesBySeverity].sort((a, b) => {
      const left = cost[a.id];
      const right = cost[b.id];
      if (left === undefined && right === undefined) return 0;
      if (left === undefined) return 1;
      if (right === undefined) return -1;
      // Total, not mean. Ranking by mean puts a rule that evaluated once above one that evaluated two dozen times for a
      // fraction of the cost, so the operator who sorts this column to find what to tune is handed the wrong rule first.
      return right.total_eval_ns - left.total_eval_ns;
    });
  }, [sortActive, rulesBySeverity, cost]);

  const reload = useCallback(async (): Promise<void> => {
    const seq = ++reloadSeqRef.current;
    const [excl, ruleDocs, ruleSettings, matchCounts, evalStats] = await Promise.all([
      listDetectionExclusions(),
      fetchRuleDocs(),
      listDetectionRuleSettings(),
      // Recovered rather than fatal: the counts are evidence for a decision, and losing them should grey out one column, not
      // stop an operator reaching the mode control on a page whose other three reads succeeded.
      listDetectionRuleMatchCounts().catch(() => null),
      // Caught separately so one column's failure does not blank the other, and so neither can fail the page: both are evidence
      // beside a control, and a table that will not render is worse than a table with one column saying it has nothing to say.
      listDetectionRuleEvalStats().catch(() => null),
    ]);
    if (!mountedRef.current || seq !== reloadSeqRef.current) return;
    setExclusions(excl);
    setRules(ruleDocs);
    setSettings(ruleSettings);
    setObservedUnavailable(matchCounts === null);
    setCostUnavailable(evalStats === null);
    if (evalStats === null) {
      // Dropped rather than kept, because unavailable has to mean the component HOLDS nothing. Keeping the previous map is
      // invisible in the cells, which short-circuit to "unavailable" before reading it, and visible in the SORT, which would
      // order the table by figures the same screen reports as unavailable. An operator following that ranking is following
      // numbers from before the outage while being told there are none.
      setCost({});
      setCostDays(0);
    } else {
      setCost(Object.fromEntries(evalStats.stats.map((s) => [s.rule_id, s])));
      setCostDays(evalStats.days);
    }
    if (matchCounts !== null) {
      setObserved(Object.fromEntries(matchCounts.counts.map((c) => [c.rule_id, c])));
      setObservedDays(matchCounts.days);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    setError(null);
    reload()
      .catch((err: unknown) => {
        if (!cancelled) setError(errMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [reload]);

  const runMutation = useCallback(
    async (op: () => Promise<unknown>): Promise<void> => {
      setActionError(null);
      setMutating(true);
      try {
        await op();
        await reload();
      } catch (err: unknown) {
        setActionError(errMessage(err));
      } finally {
        if (mountedRef.current) setMutating(false);
      }
    },
    [reload],
  );

  const handleAddExclusion = useCallback(() => {
    // Trim before sending: the UI validates on trimmed input, so persisting the raw string would let stray
    // leading/trailing whitespace into glob/substring matches and the audit reason. runMutation never rejects
    // (it captures errors into actionError), so the trailing catch is a belt-and-braces no-op for the linters.
    runMutation(async () => {
      await createDetectionExclusion({
        rule_id: formRuleID,
        match_type: formMatchType,
        value: formValue.trim(),
        reason: formReason.trim(),
        // A date input yields YYYY-MM-DD; treat it as "valid through the end of that UTC day" so the exclusion covers the whole day.
        expires_at: formExpires ? `${formExpires}T23:59:59Z` : undefined,
      });
      setFormValue("");
      setFormReason("");
      setFormExpires("");
    }).catch(() => {
      /* surfaced via actionError */
    });
  }, [runMutation, formRuleID, formMatchType, formValue, formReason, formExpires]);

  const handleDelete = useCallback(
    (id: number) => {
      // Deleting an exclusion restores detection coverage (a coverage-increasing action), so it carries a generated reason rather
      // than prompting; the audit row still records the actor, target, and timestamp.
      runMutation(() => deleteDetectionExclusion(id, "removed via admin UI")).catch(() => {
        /* surfaced via actionError */
      });
    },
    [runMutation],
  );

  // handleModeChange splits on whether the new mode makes the rule do LESS (see reducesReach). A change that restores or increases
  // what the rule does is applied immediately with a generated reason; one that reduces it first opens the reason modal so the
  // operator's justification is audited. Before monitor was selectable this read as "to alert applies, anything else prompts",
  // which happened to be the same rule while disabled was the only alternative.
  //
  // The generated reason distinguishes the two ways a rule reaches `alert`, because the audit row is read later by someone asking
  // what happened. A rule coming back from `disabled` was off and is being re-enabled. A rule coming from `monitor` was never off:
  // it was evaluating and recording, and what changed is that its matches now raise alerts. Calling that "re-enabled" would
  // misdescribe the commonest transition in the catalog now that most rules default to monitor (issue #764).
  const handleModeChange = useCallback(
    (ruleID: string, ruleTitle: string, mode: string, severity: string, priorMode: string) => {
      // isReducingMode narrows the string to the union MODE_PROMPT is keyed by. It cannot be false when reducesReach is true, since
      // monitor and disabled are the only modes ranked below alert; the compiler needs it said anyway, and it is what makes a
      // fourth mode below alert a compile error here rather than a modal with no copy.
      if (!reducesReach(priorMode, mode) || !isReducingMode(mode)) {
        runMutation(() =>
          upsertDetectionRuleSetting({
            rule_id: ruleID,
            mode,
            severity_override: severity || undefined,
            reason: generatedReason(priorMode, mode),
          }),
        ).catch(() => {
          /* surfaced via actionError */
        });
        return;
      }
      setModalError(null);
      setPendingMode({ ruleID, ruleTitle, mode, severity });
    },
    [runMutation],
  );

  // handleSeverityChange tweaks only the severity override (the rule's alerting on/off is unchanged), so it applies immediately
  // with a generated reason.
  const handleSeverityChange = useCallback(
    (ruleID: string, mode: string, severity: string) => {
      runMutation(() =>
        upsertDetectionRuleSetting({
          rule_id: ruleID,
          mode,
          severity_override: severity || undefined,
          reason: "severity override changed via admin UI",
        }),
      ).catch(() => {
        /* surfaced via actionError */
      });
    },
    [runMutation],
  );

  // confirmPendingMode applies the pending reducing change with the operator's reason. It keeps its own try/catch (rather than
  // reusing runMutation) so a failure surfaces inside the still-open modal instead of the page-level banner.
  const confirmPendingMode = useCallback(
    (reason: string) => {
      const pending = pendingMode;
      if (!pending) return;
      setModalError(null);
      setMutating(true);
      (async () => {
        try {
          await upsertDetectionRuleSetting({
            rule_id: pending.ruleID,
            mode: pending.mode,
            severity_override: pending.severity || undefined,
            reason,
          });
          await reload();
          if (mountedRef.current) setPendingMode(null);
        } catch (err: unknown) {
          if (mountedRef.current) setModalError(errMessage(err));
        } finally {
          if (mountedRef.current) setMutating(false);
        }
      })().catch(() => {
        /* inner try/catch handles all paths */
      });
    },
    [pendingMode, reload],
  );

  const cancelPendingMode = useCallback(() => {
    setPendingMode(null);
    setModalError(null);
  }, []);

  const addDisabled = !formRuleID || !formMatchType || !formValue.trim() || !formReason.trim();

  return (
    <>
      <PageHeader
        title="Detection tuning"
        subtitle="False-positive exclusions and per-rule mode the detection engine consults at evaluation time"
      />
      {loading && <EmptyState>Loading detection configuration...</EmptyState>}
      {error && !loading && <EmptyState>Error: {error}</EmptyState>}
      {actionError && (
        <div className="detection-config__error" role="alert">
          {actionError}
        </div>
      )}

      {!loading && !error && (
        <>
          <section className="detection-config__section">
            <h2 className="detection-config__heading">Exclusions</h2>
            {canWrite && (
              <div className="detection-config__form">
                <Select
                  label="Rule"
                  id="dc-rule"
                  inline={false}
                  value={formRuleID}
                  onChange={(e) => {
                    // Selecting a rule narrows the match-type picker to that rule's supported set and resets the selection to the
                    // first supported type, so a stale unsupported match type from a previous rule can never be submitted.
                    const ruleID = e.target.value;
                    setFormRuleID(ruleID);
                    setFormMatchType(supportedMatchTypesFor(ruleID)[0] ?? "");
                  }}
                >
                  <option value="">Select a rule...</option>
                  {rulesByName.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.doc.title}
                    </option>
                  ))}
                </Select>
                <Select
                  label="Match type"
                  id="dc-match"
                  inline={false}
                  value={formMatchType}
                  disabled={supportedMatchTypes.length === 0}
                  onChange={(e) => {
                    setFormMatchType(e.target.value);
                  }}
                >
                  {supportedMatchTypes.length === 0 ? (
                    <option value="">Select a rule first...</option>
                  ) : (
                    supportedMatchTypes.map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))
                  )}
                </Select>
                <div className="detection-config__form-field--full">
                  <Input
                    label="Value"
                    id="dc-value"
                    value={formValue}
                    onChange={(e) => {
                      setFormValue(e.target.value);
                    }}
                    placeholder="*/MyApp/versions/*"
                  />
                </div>
                <div className="detection-config__form-field--full">
                  <Input
                    label="Reason"
                    id="dc-reason"
                    value={formReason}
                    onChange={(e) => {
                      setFormReason(e.target.value);
                    }}
                    placeholder="why this is benign"
                  />
                </div>
                <Input
                  label="Expires (optional)"
                  id="dc-expires"
                  type="date"
                  value={formExpires}
                  onChange={(e) => {
                    setFormExpires(e.target.value);
                  }}
                />
                <div className="detection-config__form-actions">
                  <Button variant="primary" disabled={addDisabled || mutating} onClick={handleAddExclusion}>
                    Add exclusion
                  </Button>
                </div>
              </div>
            )}
            {exclusions.length === 0 ? (
              <EmptyState>No exclusions configured.</EmptyState>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Match type</th>
                    <th>Value</th>
                    <th>Reason</th>
                    <th>Expires</th>
                    <th>Created by</th>
                    {canWrite && <th aria-label="actions" />}
                  </tr>
                </thead>
                <tbody>
                  {exclusions.map((ex) => (
                    <tr key={ex.id}>
                      <td>{ex.rule_id || "(shared)"}</td>
                      <td>{ex.match_type}</td>
                      <td>
                        <code>{ex.value}</code>
                      </td>
                      <td>{ex.reason}</td>
                      <td>{ex.expires_at ? ex.expires_at.split("T")[0] : "never"}</td>
                      <td>{ex.created_by_label || ex.created_by}</td>
                      {canWrite && (
                        <td>
                          <Button
                            variant="alert"
                            disabled={mutating}
                            onClick={() => {
                              handleDelete(ex.id);
                            }}
                            title="Delete this exclusion"
                          >
                            Delete
                          </Button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </section>

          <section className="detection-config__section">
            <h2 className="detection-config__heading">Rule modes</h2>
            {/*
              Rendered visibly rather than left in the Observed header's `title`. A native tooltip on a non-focusable th reaches
              neither keyboard nor touch users, and this is the caveat that stops a bare number beside a promote control reading
              as a forecast of alert volume, so it is exactly the sentence that must not be the one only some readers get.
            */}
            <p className="detection-config__note">
              {observedUnavailable ? (
                OBSERVED_UNAVAILABLE_TOOLTIP
              ) : (
                <>
                  <strong>Observed</strong> {observedNoteBody(observedDays)}
                </>
              )}
            </p>
            {/*
              The Cost caveat gets the same treatment for the same reason. It had been left in the header's `title`, which a
              non-focusable th only surfaces on pointer hover, so the sentence that stops the number reading as a per-alert cost
              was the one keyboard and touch users did not get.
            */}
            <p className="detection-config__note">
              {costUnavailable ? (
                COST_UNAVAILABLE_TOOLTIP
              ) : (
                <>
                  <strong>Cost</strong> {costNoteBody(costDays)}
                </>
              )}
            </p>

            <Table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th title="The severity each rule declares in the catalog. It applies whenever no override is set below.">
                    Default severity
                  </th>
                  {/* The window is in the header text, not only in each cell's hover, so every reader knows what the numbers cover. */}
                  <th>Observed{observedUnavailable || observedDays === 0 ? "" : ` (${String(observedDays)}d)`}</th>
                  {/*
                    A real button rather than a click handler on the th, so the sort is reachable by keyboard and announced as a
                    control; the th carries aria-sort so the order is stated rather than left implied by the label.
                  */}
                  <th
                    title={costUnavailable ? COST_UNAVAILABLE_TOOLTIP : costColumnTooltip(costDays)}
                    aria-sort={sortActive ? "descending" : "none"}
                  >
                    <button
                      type="button"
                      className="detection-config__sort-button"
                      aria-pressed={sortActive}
                      disabled={!haveCost}
                      onClick={() => {
                        setSortByCost((on) => !on);
                      }}
                    >
                      Cost{costUnavailable || costDays === 0 ? "" : ` (${String(costDays)}d)`}
                      {sortActive ? " (slowest first)" : ""}
                    </button>
                  </th>
                  <th title={MODE_COLUMN_TOOLTIP}>Mode</th>
                  <th title="Replaces the rule's default severity on every alert it raises. (none) keeps the default.">
                    Severity override
                  </th>
                </tr>
              </thead>
              <tbody>
                {rulesForTable.map((r) => {
                  const setting = globalSetting(settings, r.id);
                  // The rule's OWN default when no operator setting applies, not a constant (issue #764). Sixty-six imported
                  // rules ship in monitor, so falling back to "alert" both displayed them as alerting and, because this value is
                  // what handleSeverityChange resubmits, silently promoted one the moment an operator touched only its severity.
                  const mode = setting?.mode ?? r.default_mode ?? "alert";
                  const severity = setting?.severity_override ?? "";
                  return (
                    <tr key={r.id}>
                      <td>
                        {r.doc.title}
                        <br />
                        <code className="detection-config__rule-id">{r.id}</code>
                      </td>
                      <td className="detection-config__default-severity">{r.doc.severity || "(unspecified)"}</td>
                      <td className="detection-config__observed">
                        {renderObserved(observed[r.id], r.id, observedDays, observedUnavailable)}
                      </td>
                      <td className="detection-config__observed">{renderCost(cost[r.id], r.id, costDays, costUnavailable)}</td>
                      <td>
                        <Select
                          label=""
                          id={`dc-mode-${r.id}`}
                          value={mode}
                          disabled={!canWrite || mutating}
                          aria-label={`mode for ${r.id}`}
                          onChange={(e) => {
                            handleModeChange(r.id, r.doc.title, e.target.value, severity, mode);
                          }}
                        >
                          {modeOptions(mode).map((m) => (
                            <option key={m} value={m}>
                              {m}
                            </option>
                          ))}
                        </Select>
                      </td>
                      <td>
                        <Select
                          label=""
                          id={`dc-sev-${r.id}`}
                          value={severity}
                          disabled={!canWrite || mutating}
                          aria-label={`severity override for ${r.id}`}
                          onChange={(e) => {
                            handleSeverityChange(r.id, mode, e.target.value);
                          }}
                        >
                          {SEVERITIES.map((s) => (
                            <option key={s || "none"} value={s}>
                              {s || "(none)"}
                            </option>
                          ))}
                        </Select>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          </section>
        </>
      )}

      {pendingMode && (
        <ReasonModal
          title={`${MODE_PROMPT[pendingMode.mode].verb} "${pendingMode.ruleTitle}"?`}
          description={MODE_PROMPT[pendingMode.mode].description}
          confirmLabel={MODE_PROMPT[pendingMode.mode].confirmLabel}
          confirmVariant="alert"
          busy={mutating}
          error={modalError}
          onConfirm={confirmPendingMode}
          onCancel={cancelPendingMode}
        />
      )}
    </>
  );
}
