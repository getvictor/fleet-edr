import { AppControlApiError, ReauthRequiredError } from "../../api";

// applyAppControlSubmitError centralises the error-mapping each app-control modal repeats inside its submit-try-catch.
// Sonar flagged the duplicated catch blocks across AddRuleModal / EditRuleModal / ConfirmActionModal as a
// new_duplicated_lines_density violation on PR #189; collapsing the mapping here keeps the per-modal handler one line.
//
// Returns true when the error was a ReauthRequiredError: the caller MUST return early in that case because useReauthRetry's
// modal is mounted as a sibling and will re-run the original call after the reauth completes. Returns false for every other
// error (which has been mapped onto setFormError) so the caller can fall through to its `finally { setBusy(false) }`.
export function applyAppControlSubmitError(
  err: unknown,
  setFormError: (msg: string) => void,
  codeMap: ReadonlyMap<string, string>,
  fallback: string,
): boolean {
  if (err instanceof ReauthRequiredError) {
    // useReauthRetry's modal mounts as a sibling; the user finishes the reauth and the original call retries on its own.
    return true;
  }
  if (err instanceof AppControlApiError) {
    setFormError(codeMap.get(err.code) ?? err.message);
    return false;
  }
  if (err instanceof Error) {
    setFormError(err.message);
    return false;
  }
  setFormError(fallback);
  return false;
}
