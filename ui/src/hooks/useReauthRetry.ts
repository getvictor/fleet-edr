// useReauthRetry — Phase 5 reauth retry wrapper. Wraps an async
// mutation; on ReauthRequiredError, opens a per-flow reauth prompt
// (rendered by the caller via the returned `modal` props) and
// retries the original call once the operator completes the
// challenge. Cancellation surfaces the original gate-deny so the
// mutation's onError fires (rather than silently succeeding) — the
// operator deserves to know the action didn't land.
//
// Challenge-level single-flight: a flurry of clicks while the modal
// is open share ONE challenge / modal cycle. Only the first click
// opens the modal; subsequent clicks await the same resolution
// promise. After the operator completes the challenge, EACH click
// retries fn(...args) independently, so the mutation runs once per
// click. The destructive actions this hook wraps today
// (host.kill_process and alert.resolve) are idempotent at the agent
// / DB level (the agent dedupes kill on the same PID; two
// alert-status PUTs with the same target status are a no-op), so
// per-click retries land at the correct end state. Coalescing the
// retried mutation itself would require fingerprinting args across
// concurrent calls, which isn't worth the complexity for v1.

import { useCallback, useRef, useState } from "react";
import { ReauthRequiredError } from "../api";
import type { ReauthChallenge } from "../api";

type AsyncFn<A extends readonly unknown[], R> = (...args: A) => Promise<R>;

// ReauthModalProps is the bundle the hook hands back so the caller
// can render <ReauthModal {...modal} /> alongside the action button.
// Keeping the modal as a side-channel rather than a Context lets each
// adoption site colocate the prompt with its mutation; no global
// provider plumbing required.
export interface ReauthModalProps {
  open: boolean;
  challenge: ReauthChallenge | null;
  // resolve fires when the operator either completes the reauth
  // (true) or cancels (false). The hook awaits this internally; the
  // caller wires it to the modal's "Confirm" / "Cancel" buttons.
  resolve: (success: boolean) => void;
}

export interface UseReauthRetry<A extends readonly unknown[], R> {
  call: AsyncFn<A, R>;
  modal: ReauthModalProps;
}

export function useReauthRetry<A extends readonly unknown[], R>(
  fn: AsyncFn<A, R>,
): UseReauthRetry<A, R> {
  const [open, setOpen] = useState(false);
  const [challenge, setChallenge] = useState<ReauthChallenge | null>(null);
  // Single-flight: collapse a flurry of concurrent retries into one
  // modal cycle. The promise resolves to the operator's
  // success/cancel verdict; everyone awaiting it gets the same
  // answer.
  const inflight = useRef<Promise<boolean> | null>(null);
  const resolverRef = useRef<((ok: boolean) => void) | null>(null);

  const call = useCallback(async (...args: A): Promise<R> => {
    try {
      return await fn(...args);
    } catch (err) {
      if (!(err instanceof ReauthRequiredError)) throw err;
      // First click into the reauth window opens the modal; later
      // clicks share the same in-flight promise.
      if (!inflight.current) {
        setChallenge(err.challenge);
        setOpen(true);
        inflight.current = new Promise<boolean>((r) => { resolverRef.current = r; });
      }
      const ok = await inflight.current;
      // Tear down for the NEXT reauth cycle. The ref is the source
      // of truth for "is a modal currently up"; the React state is
      // mirrored for the renderer.
      inflight.current = null;
      resolverRef.current = null;
      setOpen(false);
      setChallenge(null);
      if (!ok) {
        // Operator cancelled. Surface the original deny so the
        // mutation's onError sees the failure rather than a silent
        // no-op — the action genuinely didn't land.
        throw err;
      }
      return await fn(...args);
    }
  }, [fn]);

  const resolve = useCallback((ok: boolean) => {
    // Double-resolve safety: only the first call wins. Without this,
    // a quick "Confirm" then "Cancel" would unblock the awaiter
    // twice and corrupt the in-flight promise's state.
    const r = resolverRef.current;
    if (!r) return;
    resolverRef.current = null;
    r(ok);
  }, []);

  return { call, modal: { open, challenge, resolve } };
}
