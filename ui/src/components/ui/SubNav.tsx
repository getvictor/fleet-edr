import { Link, useLocation } from "react-router";
import "./SubNav.scss";

export interface SubNavItem {
  readonly to: string;
  readonly label: string;
}

interface SubNavProps {
  readonly items: readonly SubNavItem[];
  // label names the group for assistive technology, e.g. "Rules views". A page can hold more than one navigation, so the landmark
  // needs saying which this is.
  readonly label: string;
}

// SubNav is the second level of navigation within a section: a row of links, one per surface, with the one being read marked.
//
// Deliberately a nav of links rather than an ARIA tablist, matching the host page's graph and timeline switch and for the reason
// stated there: the tablist role promises arrow-key navigation between tabs and a tabpanel relationship this does not implement,
// while a nav with aria-current is exactly what this is. Each item is a real route, so an operator can link to and reload the
// surface they are on.
export function SubNav({ items, label }: SubNavProps) {
  const { pathname } = useLocation();
  return (
    <nav className="sub-nav" aria-label={label}>
      {items.map((item) => {
        // A surface is current on its own path and anything below it, so a rule's detail keeps the catalogue's tab marked rather
        // than leaving the row looking as though none of it applies.
        const current = pathname === item.to || pathname.startsWith(`${item.to}/`);
        return (
          <Link
            key={item.to}
            to={item.to}
            className={`sub-nav__item${current ? " sub-nav__item--current" : ""}`}
            aria-current={current ? "page" : undefined}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
