import classnames from "classnames";
import { Link, useLocation } from "react-router-dom";
import "./TopNav.scss";
import { useCan, PermissionAction } from "../../permissions-core";

interface NavLink {
  to: string;
  label: string;
  // action gates the entry on the operator's effective permission set: the entry is
  // hidden when the action is absent. Undefined means the destination is not gated by
  // a dedicated read action (wave-1 Coverage has no `coverage.read`), so it shows for
  // every authenticated operator. Hiding is presentation only; the server still
  // enforces every read on the destination surface.
  action?: string;
}

const LINKS: NavLink[] = [
  { to: "/", label: "Hosts", action: PermissionAction.HostRead },
  { to: "/alerts", label: "Alerts", action: PermissionAction.AlertRead },
  { to: "/app-control", label: "Application control", action: PermissionAction.AppControlRead },
  { to: "/coverage", label: "Coverage" },
];

interface TopNavProps {
  // user + onLogout are optional for pre-Phase-3 callers. Post-Phase-3 both are set
  // from App.tsx whenever a session is active; when absent we just hide the identity
  // + logout UI.
  readonly user?: { id: number; email: string };
  // authMethod is the session's authn flow ("oidc" / "local_password").
  // When the session was minted via the break-glass flow, a small badge
  // signals that the operator is NOT in a normal SSO session.
  readonly authMethod?: string;
  readonly onLogout?: () => void;
}

// authMethodLabel turns the wire-shape AuthMethod ("oidc" /
// "local_password") into operator-friendly copy. break-glass is the
// only case worth surfacing — an OIDC session is the default and
// doesn't need a badge.
function authMethodLabel(authMethod?: string): string | null {
  if (authMethod === "local_password") return "Break-glass";
  return null;
}

export function TopNav({ user, authMethod, onLogout }: TopNavProps) {
  const location = useLocation();
  const can = useCan();
  // Hide nav entries the operator's role does not confer. An entry with no gating
  // action (Coverage) always shows. Presentation only: the route guards + server
  // still enforce access independently.
  const visibleLinks = LINKS.filter((link) => link.action === undefined || can(link.action));

  return (
    <nav className="top-nav">
      <div className="top-nav__inner">
        <div className="top-nav__brand">
          <span className="top-nav__logo-mark">F</span>
          <span className="top-nav__logo-text">
            Fleet <span className="top-nav__logo-accent">EDR</span>
          </span>
        </div>
        <ul className="top-nav__links">
          {visibleLinks.map((link) => {
            const isActive = location.pathname === link.to
              || (link.to !== "/" && location.pathname.startsWith(link.to));
            return (
              <li key={link.to}>
                <Link
                  to={link.to}
                  className={classnames("top-nav__link", {
                    "top-nav__link--active": isActive,
                  })}
                >
                  {link.label}
                </Link>
              </li>
            );
          })}
        </ul>
        {user && onLogout && (
          <div className="top-nav__account">
            <span className="top-nav__avatar" aria-hidden="true">
              {user.email.charAt(0) || "?"}
            </span>
            <span className="top-nav__user">{user.email}</span>
            {authMethodLabel(authMethod) && (
              <span className="top-nav__auth-method" title="This session was minted via the break-glass recovery flow.">
                {authMethodLabel(authMethod)}
              </span>
            )}
            <button
              type="button"
              className="top-nav__logout"
              onClick={onLogout}
            >
              Log out
            </button>
          </div>
        )}
      </div>
    </nav>
  );
}
