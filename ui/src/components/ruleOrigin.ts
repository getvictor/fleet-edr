// The origin the server reports for a rule written on this deployment (server/rules/api: LocalOrigin). The server records provenance
// when a document is stored rather than inferring it from a path, and this value is how the rules API reports that record, so it is
// what separates an operator's own rules from shipped ones on every page that needs to.
const localOrigin = "Locally authored";

// isLocallyAuthored reports whether a rule was written on this deployment. An absent origin, from a server that predates reporting
// one, is not locally authored as far as this can tell; callers that must distinguish "unknown" check for undefined first.
export function isLocallyAuthored(origin: string | undefined): boolean {
  return origin === localOrigin;
}
