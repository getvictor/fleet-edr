import classnames from "classnames";
import { Link, useLocation } from "react-router-dom";
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
  readonly onLogout?: () => void;
}

export function TopNav({ user, authMethod, onLogout }: TopNavProps) {
  const location = useLocation();
  const can = useCan();
  // Hide nav entries the operator's role does not confer. An entry with no gating
  // action (Coverage) always shows. Presentation only: the route guards + server
  // still enforce access independently.
  const visibleLinks = NAV_LINKS.filter((link) => link.action === undefined || can(link.action));

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
            const isActive = location.pathname === link.to || location.pathname.startsWith(`${link.to}/`);
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
          <AccountMenu user={user} authMethod={authMethod} onLogout={onLogout} />
        )}
      </div>
    </nav>
  );
}
