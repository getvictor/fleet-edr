import classnames from "classnames";
import { Link, useLocation } from "react-router-dom";
import "./TopNav.scss";

interface NavLink {
  to: string;
  label: string;
}

const LINKS: NavLink[] = [
  { to: "/", label: "Hosts" },
  { to: "/alerts", label: "Alerts" },
];

interface TopNavProps {
  // user + onLogout are optional for pre-Phase-3 callers. Post-Phase-3 both are set
  // from App.tsx whenever a session is active; when absent we just hide the identity
  // + logout UI.
  readonly user?: { id: number; email: string };
  readonly onLogout?: () => void;
}

export function TopNav({ user, onLogout }: TopNavProps) {
  const location = useLocation();

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
          {LINKS.map((link) => {
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
            <span className="top-nav__user">{user.email}</span>
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
