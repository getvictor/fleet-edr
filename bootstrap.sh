#!/usr/bin/env bash
# Getting-started bootstrap for a single-VM EDR server (MySQL + server + Caddy).
#
# Generates the secret files, writes .env, and brings docker-compose.quickstart.yml
# up. Safe to re-run: it never overwrites an existing secret, so re-running will
# not rotate the enroll secret out from under already-enrolled agents.
#
# Usage:
#   EDR_DOMAIN=edr.example.com ./bootstrap.sh
#   EDR_DOMAIN=edr.example.com EDR_VERSION=v0.2.1 ./bootstrap.sh
#
# Prerequisites: Docker Engine 24+ with Compose v2, ports 80 and 443 open to the
# internet, and a DNS A/AAAA record for EDR_DOMAIN pointing at this host.
set -euo pipefail

COMPOSE_FILE="docker-compose.quickstart.yml"

die() { local msg="$1"; printf 'error: %s\n' "$msg" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
command -v openssl >/dev/null 2>&1 || die "openssl is not installed"

DOMAIN="${EDR_DOMAIN:-${1:-}}"
[[ -n "$DOMAIN" ]] || die "set EDR_DOMAIN, e.g. EDR_DOMAIN=edr.example.com ./bootstrap.sh"

VERSION="${EDR_VERSION:-latest}"
[[ "$VERSION" == "latest" ]] && \
  printf 'warning: EDR_VERSION=latest; pin a release tag for production (EDR_VERSION=vX.Y.Z)\n' >&2

mkdir -p secrets
# 0700 on the directory keeps the world-readable (0644) secret files below it
# unreadable to other local users: a 0700 dir blocks non-owners from traversing
# in, while the Docker daemon (root) still reads the files to bind-mount them.
# The files stay 0644 because the nonroot server container must read them once
# mounted (a host-owned 0600 file is unreadable inside the container).
chmod 0700 secrets

# gen_secret <file> <generator-command...>: write only if the file is absent or
# empty. Command substitution strips the generator's trailing newline so the
# secret file has no stray bytes.
gen_secret() {
	local f="$1"; shift
	if [[ -s "$f" ]]; then
		printf 'keeping existing %s\n' "$f"
		return
	fi
	printf '%s' "$("$@")" > "$f"
	printf 'generated %s\n' "$f"
}

gen_secret secrets/mysql_root openssl rand -hex 24
gen_secret secrets/secret_key openssl rand -hex 32
gen_secret secrets/enroll_secret openssl rand -base64 32

# edr_dsn embeds the MySQL root password and must stay in sync with it, so it is
# derived from mysql_root rather than generated independently.
if [[ ! -s secrets/edr_dsn ]]; then
	printf 'root:%s@tcp(mysql:3306)/edr?parseTime=true&tls=false' "$(cat secrets/mysql_root)" > secrets/edr_dsn
	printf 'generated secrets/edr_dsn\n'
fi
# 0644, not 0600: Compose bind-mounts a file secret into the container with the
# host file's owner and mode (the uid/gid/mode long-syntax options are Swarm
# only and ignored here), and the server image runs as nonroot, so a 0600 file
# owned by this host user is unreadable inside the container and the server
# crash-loops on "permission denied". World-readable is acceptable on this
# single-tenant VM: the file-secret win we keep is that the value never lands in
# `docker inspect`, the process environment, or an image layer.
chmod 0644 secrets/*

# Rewrite only EDR_DOMAIN and EDR_VERSION, preserving any operator-added settings
# (OTEL_* export config, EDR_RETENTION_DAYS overrides, etc.) so a rerun does not
# silently wipe them. This keeps the "safe to re-run" promise for .env, not just
# for the secret files.
tmp_env="$(mktemp)"
if [[ -f .env ]]; then
	grep -Ev '^(EDR_DOMAIN|EDR_VERSION)=' .env > "$tmp_env" || true
fi
{
	printf 'EDR_DOMAIN=%s\n' "$DOMAIN"
	printf 'EDR_VERSION=%s\n' "$VERSION"
	cat "$tmp_env"
} > .env
rm -f "$tmp_env"
printf 'wrote .env\n'

docker compose -f "$COMPOSE_FILE" up -d

cat <<EOF

Stack is starting. Caddy is requesting a Let's Encrypt certificate for $DOMAIN
(ports 80 and 443 must be reachable from the internet and DNS must resolve here).

Next steps:
  1. Enroll secret. Put this in /etc/fleet-edr.conf on each Mac as EDR_ENROLL_SECRET:
       $(cat secrets/enroll_secret)
  2. Server URL for the agent (EDR_SERVER_URL): https://$DOMAIN
  3. Redeem the break-glass admin. Grab the one-time URL from the logs and open it in a browser:
       docker compose -f $COMPOSE_FILE logs server | grep -A4 BREAK-GLASS
  4. Once the certificate is issued, confirm the server is up:
       curl -s https://$DOMAIN/readyz
  5. Open the console: https://$DOMAIN/ui/
EOF
