interface NoAccessProps {
  // surface is an optional human label for what the operator tried to reach, e.g.
  // "Application control". When set it is woven into the message.
  readonly surface?: string;
}

// NoAccess is the graceful denial state: a clear, human-readable message shown when
// an operator reaches a surface or action their role does not permit. It replaces the
// raw `Error: API error: 403` that leaked through before capability gating (ADR-0012).
//
// It is intentionally generic and reveals nothing beyond "you lack access": no role
// names and no required-permission identifiers. That makes it safe to show on a deep-link by
// an operator who should not even know the surface exists.
export function NoAccess({ surface }: NoAccessProps) {
  return (
    <div className="no-access" role="alert">
      <h2 className="no-access__title">You don&apos;t have access</h2>
      <p className="no-access__body">
        {surface
          ? `Your role doesn't include access to ${surface}.`
          : "Your role doesn't include access to this page."}{" "}
        Contact your administrator if you think this is a mistake.
      </p>
    </div>
  );
}
