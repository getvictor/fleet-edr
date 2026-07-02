// formatPlatform maps the server's host platform value to a display label. The server sends darwin | windows | linux, or "" for a host
// that has sent events but never enrolled; the empty case renders "unknown". An unrecognized value falls back to itself so a future
// platform shows through rather than disappearing. Pure logic, kept out of the component file so it is unit-testable and does not trip
// react-refresh's only-export-components rule.
export function formatPlatform(platform: string): string {
  switch (platform) {
    case "darwin":
      return "macOS";
    case "windows":
      return "Windows";
    case "linux":
      return "Linux";
    case "":
      return "unknown";
    default:
      return platform;
  }
}
