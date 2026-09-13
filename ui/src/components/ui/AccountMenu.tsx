import { Link } from "react-router";
import { useCan, PermissionAction } from "../../permissions-core";
import { roleLabel } from "../../roles";
import { useDismiss } from "./useDismiss";
import "./AccountMenu.scss";

interface AccountMenuProps {
  readonly user: { id: number; email: string };
  // authMethod is the session's authn flow; "local_password" surfaces a break-glass badge.
  readonly authMethod?: string;
  // roles are the session's role ids, named inside the dropdown so an operator can see what their session carries. Undefined (an older
  // server that does not send them) names no role; an empty array is a session with none.
  readonly roles?: readonly string[];
  readonly onLogout: () => void;
}

function authMethodLabel(authMethod?: string): string | null {
  if (authMethod === "local_password") return "Break-glass";
  return null;
}

// signInLabel names how the session was minted, for the dropdown: SSO is any OIDC provider, so it is not named after one.
function signInLabel(authMethod?: string): string | null {
  switch (authMethod) {
    case "oidc":
      return "SSO";
    case "local_password":
      return "break-glass";
    default:
      return null;
  }
}

// AccountMenu is the top-right avatar dropdown: it carries the entry point to the Admin
// settings area (gated on sso.manage so only admins see it), Detection tuning (gated on
// detection_config.read, so admins and senior analysts see it), Documentation, and Log
// out. The "Admin settings" link is the only way into the settings area, matching the
// design. Closes on outside-click and Escape. Implemented as a disclosure (trigger carries
// aria-expanded) rather than the ARIA menu pattern: the items are plain links/buttons, so
// menu/menuitem roles would promise arrow-key navigation that this control does not provide.
export function AccountMenu({ user, authMethod, roles, onLogout }: AccountMenuProps) {
  const can = useCan();
  const { open, setOpen, ref } = useDismiss<HTMLDivElement>();

  const badge = authMethodLabel(authMethod);
  const signIn = signInLabel(authMethod);

  return (
    <div className="account-menu" ref={ref}>
      <button
        type="button"
        className="account-menu__trigger"
        aria-haspopup="true"
        aria-expanded={open}
        // The email is deliberately not rendered in the always-visible bar (shoulder-surfing): the avatar shows only the initial and
        // the signed-in identity is revealed in the dropdown on click. aria-label keeps the trigger named for assistive tech.
        aria-label="Account menu"
        onClick={() => { setOpen((v) => !v); }}
      >
        <span className="account-menu__avatar" aria-hidden="true">{user.email.charAt(0) || "?"}</span>
        {badge !== null && (
          <span className="account-menu__auth-method" title="This session was minted via the break-glass recovery flow.">
            {badge}
          </span>
        )}
        <span className="account-menu__chevron" aria-hidden="true" />
      </button>
      {open && (
        <div className="account-menu__dropdown">
          <div className="account-menu__header">
            <div className="account-menu__email">{user.email}</div>
            {roles !== undefined && (
              <div className="account-menu__session">
                Role: {roles.length === 0 ? "none" : roles.map(roleLabel).join(", ")}
              </div>
            )}
            {signIn !== null && <div className="account-menu__session">Signed in with {signIn}</div>}
          </div>
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
