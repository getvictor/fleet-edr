import classnames from "classnames";
import { Link, useLocation } from "react-router";
import "./TopNav.scss";
import { useCan } from "../../permissions-core";
import { AccountMenu } from "./AccountMenu";
import { NAV_LINKS } from "./nav-links";

interface TopNavProps {
  // user + onLogout are optional for pre-Phase-3 callers. Post-Phase-3 both are set
  // from App.tsx whenever a session is active; when absent we just hide the identity
  // + logout UI.
  readonly user?: { id: number; email: string };
  // authMethod is the session's authn flow ("oidc" / "local_password").
  // When the session was minted via the break-glass flow, a small badge
  // signals that the operator is NOT in a normal SSO session.
  readonly authMethod?: string;
  // roles are the session's role ids, named in the account menu.
  readonly roles?: readonly string[];
  readonly onLogout?: () => void;
}

export function TopNav({ user, authMethod, roles, onLogout }: TopNavProps) {
  const location = useLocation();
  const can = useCan();
  // Hide nav entries the operator's role does not confer. Every entry names a gating action, so there is no entry that always
  // shows: one left ungated to guarantee the landing redirect a match is what sent an operator holding nothing to a page that
  // then refused their read. Presentation only: the route guards + server still enforce access independently.
  const visibleLinks = NAV_LINKS.filter((link) => can(link.action));

  return (
    <nav className="top-nav">
      <div className="top-nav__inner">
        <div className="top-nav__brand">
          <span className="top-nav__logo-text">
            Fleet <span className="top-nav__logo-accent">EDR</span>
          </span>
        </div>
        <ul className="top-nav__links">
          {visibleLinks.map((link) => {
            const onPath = (path: string) => location.pathname === path || location.pathname.startsWith(`${path}/`);
            // Active on the entry's own path or on any sibling surface of its section, so a section's tabs do not each look like
            // a different place in the top navigation.
            const isActive = onPath(link.to) || (link.siblings?.some(onPath) ?? false);
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
          <AccountMenu user={user} authMethod={authMethod} roles={roles} onLogout={onLogout} />
        )}
      </div>
    </nav>
  );
}
