#!/usr/bin/env bash
# Create the MySQL schema and the ClickHouse database one lane's dev server needs, if they are not there already.
#
# Nothing else creates them for a second worktree. docker-compose.yml seeds only `edr` (MYSQL_DATABASE) and the ClickHouse service
# comes up with no application database at all; `task db:reset` recreates only `edr`. Neither the server nor fleet-edr-migrate
# creates what is missing: migrate stops at "Unknown database" and the server stops at "Database <name> does not exist". So a lane
# whose schemas nobody made by hand could not start a server, which is what kept the Playwright suite from spawning one there
# (issue #826).
#
# IF NOT EXISTS throughout, so this never touches data: on the lane that already has its schemas it is a no-op, and it cannot be
# used to reset anything.
#
# Usage: scripts/ensure-lane-schemas.sh <schema>
set -euo pipefail

readonly SCHEMA="${1:-}"
if [[ -z "$SCHEMA" ]]; then
  echo "usage: $0 <schema>" >&2
  exit 2
fi

# The name reaches a shell, a SQL statement and a URL, so it is validated rather than trusted. The lanes are `edr` and `edr2`;
# anything outside this shape is a caller bug, and rejecting it here keeps a stray value from reaching the servers as SQL.
if [[ ! "$SCHEMA" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "$0: schema must be alphanumeric or underscore (got '$SCHEMA')" >&2
  exit 2
fi

# Ports match docker-compose.yml: dev MySQL on 33306, ClickHouse's HTTP interface on 18123. The HTTP interface rather than
# clickhouse-client because curl is always present and the client is not, and rather than `docker exec` because that would tie
# this to a container name the compose project can change.
mysql -uroot -h127.0.0.1 -P33306 -e "CREATE DATABASE IF NOT EXISTS ${SCHEMA} CHARACTER SET utf8mb4"
curl -sS --fail-with-body 'http://127.0.0.1:18123/' --data-binary "CREATE DATABASE IF NOT EXISTS ${SCHEMA}"

echo "$0: ${SCHEMA} exists in MySQL and ClickHouse"
