import type { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { useCan, PermissionAction } from "../../permissions-core";
import "./SettingsLayout.scss";

// SettingsLayout wraps the admin settings pages with a shared sub-navigation between the
// sections the operator can access (the design's Admin settings area). It is mounted by the
// router around each settings page, so the individual page components stay free of nav chrome
// (and their unit tests can render bare). Sections the operator lacks permission for are
// omitted; the server chokepoint remains the authority (ADR-0012).
const SECTIONS = [
  { to: "/admin/settings/sso", label: "Single sign-on", action: PermissionAction.SSOManage },
  { to: "/admin/settings/webhooks", label: "Webhooks", action: PermissionAction.WebhookManage },
  { to: "/admin/settings/users", label: "Users", action: PermissionAction.UserRead },
  { to: "/admin/settings/service-accounts", label: "Service accounts", action: PermissionAction.ServiceAccountRead },
] as const;

export function SettingsLayout({ children }: { readonly children: ReactNode }) {
  const can = useCan();
  const { pathname } = useLocation();
  const sections = SECTIONS.filter((s) => can(s.action));

  return (
    <div className="settings-layout">
      <nav className="settings-layout__nav" aria-label="Settings sections">
        {sections.map((s) => {
          const active = pathname === s.to || pathname.startsWith(s.to + "/");
          return (
            <Link
              key={s.to}
              to={s.to}
              className={active ? "settings-layout__link settings-layout__link--active" : "settings-layout__link"}
              aria-current={active ? "page" : undefined}
            >
              {s.label}
            </Link>
          );
        })}
      </nav>
      <div className="settings-layout__content">{children}</div>
    </div>
  );
}
