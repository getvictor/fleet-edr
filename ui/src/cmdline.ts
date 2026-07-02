// formatCommandLine renders an argument vector as a faithful one-line command: an argument containing whitespace or a double quote
// is double-quoted (inner quotes escaped) so a single argument with spaces stays visually distinct from two arguments. Conviction
// evidence must not misrepresent argv (issue #580 review). Falls back to the path, then "(unknown)", when no args were captured.
export function formatCommandLine(args: string[] | undefined, path: string): string {
  if (!args || args.length === 0) return path || "(unknown)";
  return args.map(quoteArg).join(" ");
}

function quoteArg(arg: string): string {
  if (arg === "") return '""';
  if (/[\s"]/.test(arg)) return `"${arg.split('"').join('\\"')}"`;
  return arg;
}
