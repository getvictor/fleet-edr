// URL predicates shared by the surfaces that render or accept a URL.
//
// Extracted because there were two functions NAMED isHTTPURL with different behaviour: one in SSOSettings that trimmed the input,
// one in RuleDetail that did not. Two validators of the same name disagreeing about what is safe is the shape of a bug nobody
// notices until the weaker one is the load-bearing check.
//
// Webhooks deliberately does NOT use this: a webhook destination must be https, not http(s), and folding that in would either
// weaken it or add a parameter whose only job is to remember which caller is which.

/**
 * isHTTPURL reports whether raw is an absolute http or https URL.
 *
 * The scheme test is an allowlist rather than a denylist of the schemes known to be dangerous today, because a denylist has to be
 * updated every time a browser grows a new one, and being wrong turns a rendered link into script execution.
 *
 * Both copies this replaced also tested `host !== ""`. That guard is unreachable and is deliberately not carried over: for the
 * two special schemes here the WHATWG parser never yields an empty host, it either throws (`http://`, `http://:80/`, `http://@/x`)
 * or promotes the first path segment (`http:///a/b` parses to host `a`). Measured, not assumed. Do not re-add it.
 */
export function isHTTPURL(raw: string): boolean {
  try {
    const { protocol } = new URL(raw.trim());
    return protocol === "http:" || protocol === "https:";
  } catch {
    // Not a parseable absolute URL: a bare path, a DOI, free text. Callers render it as plain text.
    return false;
  }
}
