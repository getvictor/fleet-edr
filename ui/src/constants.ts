// Time-unit conversions used across the UI.
//
// The agent + server speak nanosecond timestamps (Unix ns) on the wire so a
// single Math.floor() per value is enough to land in JS's millisecond clock.
// Centralising these here keeps `lastSeenNs / 1_000_000` from sprouting in
// every renderer and makes the lint catch any future "1e6" drift.
export const NANOSECONDS_PER_MILLISECOND = 1_000_000;
export const MILLISECONDS_PER_SECOND = 1_000;
export const SECONDS_PER_MINUTE = 60;
export const MINUTES_PER_HOUR = 60;
export const HOURS_PER_DAY = 24;
export const MILLISECONDS_PER_MINUTE = MILLISECONDS_PER_SECOND * SECONDS_PER_MINUTE;
export const MILLISECONDS_PER_HOUR = MILLISECONDS_PER_MINUTE * MINUTES_PER_HOUR;
export const MILLISECONDS_PER_DAY = MILLISECONDS_PER_HOUR * HOURS_PER_DAY;

// HTTP status codes the UI handles directly. Defined here rather than relying
// on a string literal table so the lint allow-list stays tight.
export const HTTP_STATUS_NO_CONTENT = 204;
export const HTTP_STATUS_UNAUTHORIZED = 401;
export const HTTP_STATUS_FORBIDDEN = 403;

// Upper bound on a stored CSRF token. The server mints URL-safe base64 of a
// 32-byte secret (~43 chars); 256 leaves headroom for a future widening
// without us editing both ends, while still rejecting obviously bogus
// payloads that ended up in sessionStorage.
export const MAX_CSRF_TOKEN_LENGTH = 256;
