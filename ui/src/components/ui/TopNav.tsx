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

export function TopNav() {
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
      </div>
    </nav>
  );
}
