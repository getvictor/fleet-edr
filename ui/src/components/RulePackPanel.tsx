import { useCallback, useEffect, useState } from "react";
import { getRulePackStatus, ReauthRequiredError, rollbackRulePack, type RulePackRollbackResult, type RulePackStatus } from "../api";
import { useReauthRetry } from "../hooks/useReauthRetry";
import { ReasonModal } from "./DetectionConfig/ReasonModal";
import { ReauthModal } from "./ReauthModal";
import { Button } from "./ui/Button";
import "./RulePackPanel.scss";

// ChangeList names the built-in rules one side of a difference holds, or nothing when there are none.
function ChangeList({ label, rules }: { readonly label: string; readonly rules: readonly string[] }) {
  if (rules.length === 0) return null;
  return (
    <details className="rule-pack__changes">
      <summary>{`${label}: ${String(rules.length)}`}</summary>
      <ul>
        {rules.map((r) => <li key={r}><code>{r}</code></li>)}
      </ul>
    </details>
  );
}

// RulePackPanel reports which generation of built-in rules the deployment runs and offers to roll it back (issue #1001). Installing the
// rules a build ships replaces the previous set, and when one of the new rules turns out to be noisy or wrong the fix is to put the
// previous set back, which the API already does.
//
// Rules the deployment wrote are never touched by a rollback. A built-in rule whose identifier one of them now holds is not restored over
// it, and the server names those after the rollback, which is when it knows them.
export function RulePackPanel({ canWrite }: { readonly canWrite: boolean }) {
  const [status, setStatus] = useState<RulePackStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  const [result, setResult] = useState<RulePackRollbackResult | null>(null);

  const refresh = useCallback(() => {
    getRulePackStatus()
      .then((s) => { setStatus(s); setError(null); })
      .catch((err: unknown) => { setError(err instanceof Error ? err.message : "Unknown error"); });
  }, []);
  useEffect(refresh, [refresh]);

  const rollback = useCallback(async (reason: string) => rollbackRulePack(reason), []);
  const { call: callRollback, modal: reauthModal } = useReauthRetry(rollback);

  const onConfirmRollback = (reason: string) => {
    setRollingBack(true);
    setRollbackError(null);
    callRollback(reason)
      .then((r) => {
        setResult(r);
        setRollbackOpen(false);
        refresh();
      })
      .catch((err: unknown) => {
        if (err instanceof ReauthRequiredError) {
          setRollbackOpen(false);
          return;
        }
        setRollbackError(err instanceof Error ? `Not rolled back: ${err.message}` : "Not rolled back.");
      })
      .finally(() => { setRollingBack(false); });
  };

  if (error !== null) return <p className="rule-pack rule-pack__note">The built-in rules status could not be loaded: {error}</p>;
  if (status === null) return null;

  return (
    <section className="rule-pack" aria-labelledby="rule-pack-heading">
      <h2 id="rule-pack-heading" className="rule-pack__heading">Built-in rules</h2>
      <p className="rule-pack__note">
        {status.current
          ? "This deployment runs the built-in rules this build carries."
          : "This deployment does not run the built-in rules this build carries."}
        {status.declined !== "" && " A set of built-in rules was rolled back and will not be reinstalled."}
      </p>
      {!status.current && (
        <>
          <ChangeList label="Rules this build adds" rules={status.added} />
          <ChangeList label="Rules this build removes" rules={status.removed} />
          <ChangeList label="Rules this build changes" rules={status.changed} />
        </>
      )}
      {result !== null && (
        <div className="rule-pack__result" role="status">
          Rolled back to the previous built-in rules. The server applies them when it next reloads its rules, within 30 seconds.
          {result.withheld.length > 0 && (
            <>
              {" "}Not restored, because a rule you wrote now uses the identifier:{" "}
              {result.withheld.map((w, i) => (
                <span key={w}>
                  {i > 0 && ", "}
                  <code>{w}</code>
                </span>
              ))}
              .
            </>
          )}
        </div>
      )}
      {canWrite && status.can_roll_back && (
        <Button size="small" variant="alert" onClick={() => { setRollbackError(null); setRollbackOpen(true); }}>
          Roll back built-in rules
        </Button>
      )}
      {rollbackOpen && (
        <ReasonModal
          title="Roll back built-in rules"
          description={
            "Restores the previous set of built-in rules and keeps this deployment from reinstalling the current one. Rules you wrote " +
            "are untouched, and a built-in rule whose identifier one of yours uses is not restored."
          }
          confirmLabel="Roll back"
          confirmVariant="alert"
          placeholder="Why are the built-in rules being rolled back?"
          busy={rollingBack}
          error={rollbackError}
          onConfirm={onConfirmRollback}
          onCancel={() => { setRollbackOpen(false); }}
        />
      )}
      <ReauthModal {...reauthModal} />
    </section>
  );
}
