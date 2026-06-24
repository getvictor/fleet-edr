import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useCan, PermissionAction } from "../../permissions-core";
import "./AccountMenu.scss";

interface AccountMenuProps {
  readonly user: { id: number; email: string };
  // authMethod is the session's authn flow; "local_password" surfaces a break-glass badge.
  readonly authMethod?: string;
  readonly onLogout: () => void;
}

function authMethodLabel(authMethod?: string): string | null {
  if (authMethod === "local_password") return "Break-glass";
  return null;
}

// AccountMenu is the top-right avatar dropdown: it carries the entry point to the Admin
// settings area (gated on sso.manage so only admins see it), Detection tuning (gated on
// detection_config.read, so admins and senior analysts see it), Documentation, and Log
// out. The "Admin settings" link is the only way into the settings area, matching the
// design. Closes on outside-click and Escape. Implemented as a disclosure (trigger carries
// aria-expanded) rather than the ARIA menu pattern: the items are plain links/buttons, so
// menu/menuitem roles would promise arrow-key navigation that this control does not provide.
export function AccountMenu({ user, authMethod, onLogout }: AccountMenuProps) {
  const can = useCan();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return undefined;
    function onDocClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const badge = authMethodLabel(authMethod);

  return (
    <div className="account-menu" ref={ref}>
      <button
        type="button"
        className="account-menu__trigger"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => { setOpen((v) => !v); }}
      >
        <span className="account-menu__avatar" aria-hidden="true">{user.email.charAt(0) || "?"}</span>
        <span className="account-menu__email">{user.email}</span>
        {badge !== null && (
          <span className="account-menu__auth-method" title="This session was minted via the break-glass recovery flow.">
            {badge}
          </span>
        )}
        <span className="account-menu__chevron" aria-hidden="true" />
      </button>
      {open && (
        <div className="account-menu__dropdown">
          <div className="account-menu__header">{user.email}</div>
          {can(PermissionAction.SSOManage) && (
            <Link
              to="/admin/settings/sso"
              className="account-menu__item account-menu__item--highlight"
              onClick={() => { setOpen(false); }}
            >
              Admin settings
            </Link>
          )}
          {can(PermissionAction.DetectionConfigRead) && (
            <Link
              to="/detection-config"
              className="account-menu__item"
              onClick={() => { setOpen(false); }}
            >
              Detection tuning
            </Link>
          )}
          <a
            href="https://github.com/getvictor/fleet-edr/tree/main/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="account-menu__item"
            onClick={() => { setOpen(false); }}
          >
            Documentation
          </a>
          <div className="account-menu__divider" />
          <button
            type="button"
            className="account-menu__item account-menu__item--logout"
            onClick={() => { setOpen(false); onLogout(); }}
          >
            Log out
          </button>
        </div>
      )}
    </div>
  );
}
