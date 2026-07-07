# sso-configuration Specification (delta)

## REMOVED Requirements

### Requirement: Environment variables seed the stored configuration on first boot only

**Reason**: SSO is now configured exclusively through the Single sign-on admin page and API backed by the durable `oidc_config` store, which is the runtime source of truth and survives restarts. The `EDR_OIDC_*` first-boot seed was a transitional bridge for env-only deployments; those deployments already had their config persisted to the store on first boot under #375, so the seed path no longer carries any deployment. The server no longer reads `EDR_OIDC_*` at all. Non-interactive stacks (the demo and local QA) seed the store programmatically through an explicit bootstrap seam rather than through server-side env ingestion.

**Migration**: None for operators: a stored record created by the original env-seed remains authoritative and is read unchanged. Setting `EDR_OIDC_*` on a fresh deployment is now inert; configure SSO under **Admin settings -> Single sign-on** after a break-glass login.
