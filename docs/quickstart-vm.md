# Quickstart: single VM with your own domain

This is the recommended way to stand up a Fleet EDR server for a pilot. You run one Linux VM with Docker, point a domain at it, and run one script. Caddy gets a Let's Encrypt certificate automatically and reverse-proxies to the server, so you manage no certificates, and because Caddy is a plain reverse proxy there is no content-inspecting WAF to flag your agents' telemetry as attacks (the failure mode you hit on a managed PaaS edge). The stack is sized for a single customer with 10 to 500 endpoints. For high availability, see the multi-replica topology in [install-server.md](install-server.md).

## What you get

`docker-compose.quickstart.yml` runs three containers on one host: MySQL, the EDR server (listening plaintext on the private Docker network only), and Caddy (the only container exposed to the internet, on ports 80 and 443). The server self-applies its schema migrations on first boot.

## Prerequisites

- A Linux VM with Docker Engine 24+ and Docker Compose v2 (`docker compose`, not `docker-compose`). A 2 vCPU / 4 GB instance is comfortable for a pilot.
- A domain you control (for example `edr.example.com`).
- Ports 80 and 443 open to the internet on the VM. Caddy needs both for the ACME certificate challenge and for serving traffic.
- A DNS `A` (and optional `AAAA`) record for your domain pointing at the VM's public IP, created before you run the script so the certificate can be issued.
- Optional but recommended beyond a short evaluation: a separate data disk for MySQL. Event telemetry dominates storage and a busy host can add many GB per day, so a dedicated disk keeps the OS root from filling. Set it up before you run the bootstrap: see [Put MySQL data on a dedicated disk](#put-mysql-data-on-a-dedicated-disk).

## Put MySQL data on a dedicated disk

Skip this for a quick evaluation. For anything longer, give MySQL its own disk rather than sharing the OS root, because event telemetry is the dominant store and a busy host can add many GB per day (tune the window with `EDR_RETENTION_DAYS`; see retention tuning in [operations.md](operations.md#retention-tuning)). The simplest approach with no Compose changes is to mount the data disk at Docker's data root (`/var/lib/docker`) before you install Docker, so the `edr-mysql-data` volume lands on it automatically.

On a fresh VM whose extra disk is still raw (confirm the device name with `lsblk`; below it is `/dev/sdb`, a 100 GB disk):

```sh
sudo mkfs.ext4 -L edr-data /dev/sdb
UUID=$(sudo blkid -s UUID -o value /dev/sdb)
sudo mkdir -p /var/lib/docker
# nofail so a detached data disk never blocks boot.
echo "UUID=$UUID  /var/lib/docker  ext4  defaults,discard,nofail  0 2" | sudo tee -a /etc/fstab
sudo mount /var/lib/docker
```

Then install Docker. Everything Docker stores, including the MySQL data volume, now lives on the dedicated disk. Confirm with `docker info --format '{{.DockerRootDir}}'` (expect `/var/lib/docker`) and `findmnt /var/lib/docker` (expect your data disk).

If Docker is already installed and running, stop it and migrate the existing data root first: `sudo systemctl stop docker`, copy the data aside with `sudo rsync -aP /var/lib/docker/ /var/lib/docker.bak/`, mount the disk as above, restore with `sudo rsync -aP /var/lib/docker.bak/ /var/lib/docker/`, then `sudo systemctl start docker`.

A full data disk stops MySQL writes (ingest returns 5xx and the server logs the error) and, because Docker's data root sits on it, affects the rest of Docker too, so keep `EDR_RETENTION_DAYS` sized to the disk and alert on disk usage.

## Steps

1. Get the repository onto the VM and change into it:

   ```sh
   git clone https://github.com/getvictor/fleet-edr.git
   cd fleet-edr
   ```

2. Point your DNS record at the VM and wait for it to resolve (`dig +short edr.example.com` should return the VM IP).

3. Run the bootstrap, passing your domain and a pinned release version:

   ```sh
   EDR_DOMAIN=edr.example.com EDR_VERSION=v0.2.1 ./bootstrap.sh
   ```

   It generates the secrets (`secrets/`), writes `.env`, and starts the stack. It is safe to re-run; it never overwrites an existing secret.

4. Wait for the certificate to be issued (usually under a minute), then confirm the server is up:

   ```sh
   curl -s https://edr.example.com/readyz
   ```

5. Redeem the break-glass admin. On first boot the server prints a one-time redemption URL (not a password) to its logs:

   ```sh
   docker compose -f docker-compose.quickstart.yml logs server | grep -A4 BREAK-GLASS
   ```

   Open that URL in a browser within its TTL and register a passkey to become admin. Then open the console at `https://edr.example.com/ui/`.

6. Deploy the agent. The bootstrap output prints your enroll secret and server URL. Put them on each Mac (`EDR_SERVER_URL` and `EDR_ENROLL_SECRET` in `/etc/fleet-edr.conf`); see [install-agent-manual.md](install-agent-manual.md) for a single Mac or [mdm-deployment.md](mdm-deployment.md) to deploy through your MDM. To keep telemetry volume down on this disk-bounded pilot, also set `EDR_PROCESS_RECONCILE_INTERVAL=5m` in `/etc/fleet-edr.conf` (default is 60s): it cuts the agent's per-process liveness heartbeats roughly fivefold with no detection impact. This is an interim setting pending the storage rework in [getvictor/fleet-edr#408](https://github.com/getvictor/fleet-edr/issues/408); revert to the default once that lands.

## Set server configuration

The server is configured entirely through environment variables (full reference: [install-server.md](install-server.md)). This stack passes `.env` through to the server container, so to change any server setting, add it to `.env` and recreate the server:

```sh
echo 'EDR_SESSION_IDLE_TIMEOUT=4h' >> .env
docker compose -f docker-compose.quickstart.yml up -d server
```

The security-critical wiring in `docker-compose.quickstart.yml` (proxy-terminated TLS, trusted proxies, the secret `*_FILE` paths) is set in the Compose file and takes precedence over `.env`, so you cannot break it from `.env` by accident.

For a sensitive value, do not put it in `.env` in plaintext (it is world-readable and shows in `docker inspect`). Use the `*_FILE` variant backed by a Docker secret, the same way the database and enroll secrets work: write the value to `secrets/<name>`, add a matching entry under both the top-level `secrets:` and the `server` service's `secrets:` in the Compose file, then set `EDR_<NAME>_FILE=/run/secrets/<name>` in `.env`. Every string setting accepts this `_FILE` form.

To see what the running server actually loaded (the image is distroless, so there is no shell to `exec` into), inspect the container's environment:

```sh
docker inspect "$(docker compose -f docker-compose.quickstart.yml ps -q server)" \
  --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^EDR_'
```

### Single sign-on (OIDC)

The quickstart boots with break-glass sign-in only (`EDR_AUTH_ALLOW_NO_OIDC=1`). Configure your identity provider in the UI: sign in with the break-glass admin (step 5), open **Admin settings -> Single sign-on**, and enter the issuer, client ID, client secret, and external URL. The form derives the redirect URI from the external URL and shows it read-only; register that exact value at your IdP. A test-connection button verifies the provider before you save, and changes apply at runtime with no restart. See [okta-setup.md](okta-setup.md) for the IdP-side steps.

Alternatively, seed the configuration from the environment on the server's first boot (useful for unattended provisioning), keeping the client secret in a Docker secret rather than `.env`:

```sh
# Client secret as a file secret (secrets/ is 0700; the file is 0644 so the nonroot server container can read it).
printf '%s' 'YOUR_OIDC_CLIENT_SECRET' > secrets/oidc_client_secret
chmod 0644 secrets/oidc_client_secret
```

Add an `oidc_client_secret` entry under both the top-level `secrets:` and the `server` service's `secrets:` in `docker-compose.quickstart.yml` (pointing at `./secrets/oidc_client_secret`), then in `.env`:

```sh
EDR_OIDC_ISSUER=https://your-idp.example.com
EDR_OIDC_CLIENT_ID=your-client-id
EDR_OIDC_REDIRECT_URL=https://edr.example.com/api/auth/callback
EDR_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
EDR_AUTH_ALLOW_NO_OIDC=0
```

Recreate the server (`docker compose -f docker-compose.quickstart.yml up -d server`). These variables seed the stored configuration on the first boot only; afterward the Single sign-on screen is the source of truth and further `EDR_OIDC_*` changes are inert. The redirect URL must exactly match what your IdP has on file.

## Operations

- **Upgrade.** Edit `EDR_VERSION` in `.env`, then pull and recreate:

  ```sh
  docker compose -f docker-compose.quickstart.yml pull server
  docker compose -f docker-compose.quickstart.yml up -d
  ```

- **Where state lives.** Durable data is in the `edr-mysql-data` Docker volume; issued certificates are in the `caddy-data` volume. Both sit under Docker's data root (`/var/lib/docker`), so they live on whatever disk backs it: mount a [dedicated data disk](#put-mysql-data-on-a-dedicated-disk) there to keep MySQL off the OS root. Back both up (a `mysqldump` schedule plus a volume snapshot). The `secrets/` directory holds the enroll secret, the deployment secret key, and the database credentials; keep a copy somewhere safe, because the secret key cannot be regenerated without invalidating every enrolled host.

- **Rotate the enroll secret.** Overwrite `secrets/enroll_secret` and `docker compose -f docker-compose.quickstart.yml restart server`. Existing host tokens are unaffected (they were derived at enroll time).

- **Add single sign-on, change other settings.** Configure SSO in the UI (**Admin settings -> Single sign-on**); see the [Single sign-on (OIDC)](#single-sign-on-oidc) section above. For other settings, see [Set server configuration](#set-server-configuration).

## Send telemetry to a collector

The server exports OpenTelemetry traces, metrics, and logs over OTLP/gRPC. It is off until you point it at a collector. To turn it on, add the endpoint to `.env` and recreate the server:

```sh
echo 'OTEL_EXPORTER_OTLP_ENDPOINT=https://ingest.us.signoz.cloud:443' >> .env
docker compose -f docker-compose.quickstart.yml up -d server
```

The URL scheme picks the transport: `http://host:4317` is plaintext (a collector on the same VM or private network), `https://host:443` uses TLS (a hosted backend). The quickstart compose forwards three OTel variables from `.env`, all optional:

- `OTEL_EXPORTER_OTLP_ENDPOINT`: the OTLP/gRPC collector URL. Unset disables export entirely.
- `OTEL_EXPORTER_OTLP_HEADERS`: comma-separated headers, used for an ingestion or auth token, for example `signoz-ingestion-key=<key>` for SigNoz Cloud or `authorization=Bearer <token>` for an OTLP gateway.
- `OTEL_RESOURCE_ATTRIBUTES`: comma-separated resource tags. Set `deployment.environment.name=production` (or `staging`, etc.) so the backend can separate this deployment's signals from others. `service.name` is already pinned to `fleet-edr-server`.

The full list of exported metrics and what to alert on is in [install-server.md](install-server.md#otel-metrics-and-logs) and [operations.md](operations.md#metrics-and-monitoring). There is no Prometheus scrape endpoint; export is OTel-only.

If you run the collector as a fourth container in this stack, reach it by its Compose service name (for example `http://collector:4317`) rather than `localhost`, because each container has its own loopback.

## Tuning MySQL for ingest throughput

If event ingest feels slow (the server logs `http request (slow)` on `POST /api/events`, or the agent's upload queue grows), the bottleneck is almost always MySQL commit latency on the data disk: each event batch is one InnoDB transaction, and commit cost is dominated by disk fsync. The stack already runs `--skip-log-bin` (no binary log) by default. The remaining knobs are disk- and RAM-specific, so they are not defaulted; add them as `command:` entries on the `mysql` service in `docker-compose.quickstart.yml`, then recreate MySQL with `docker compose -f docker-compose.quickstart.yml up -d mysql`.

Measure your disk's synchronous-write speed first, because the right `io_capacity` depends on it:

```sh
sudo dd if=/dev/zero of=/var/lib/docker/.fsynctest bs=4k count=2000 oflag=dsync; sudo rm -f /var/lib/docker/.fsynctest
```

Divide the reported throughput by 4 KiB to get the disk's sustained sync IOPS (for example 771 kB/s is ~190 IOPS, a slow network volume; 50+ MB/s is local SSD).

The knobs, in order of impact:

- **`--innodb-flush-log-at-trx-commit=2`**: fsync the redo log about once a second instead of on every commit. The biggest single win on a slow disk. Tradeoff: a host crash can lose up to ~1 second of acknowledged events. That is acceptable here because the agent keeps a local queue and re-uploads, but it is a durability change, so it is opt-in.
- **`--innodb-io-capacity=<IOPS>` and `--innodb-io-capacity-max=<2x IOPS>`**: set these to your measured disk IOPS. The default is far too high for a network volume, which makes InnoDB hoard dirty pages and then flush them in bursts that stall commits for seconds (a large latency tail). Matching the real disk speed makes flushing steady.
- **`--innodb-buffer-pool-size=<bytes>`**: keep the index-heavy `events` working set in RAM. Size it to roughly half to three-quarters of the VM's RAM. Raise it together with `io_capacity`, not alone: a larger pool holds more dirty pages, so without matching flush pacing it can make the latency tail worse on a slow disk.
- **`--innodb-max-dirty-pages-pct=10`**: on a slow disk, keep the dirty set small so InnoDB flushes continuously rather than in storms.

Example for a slow ~190 IOPS network volume on an 8 GB box:

```yaml
command:
  - --skip-log-bin
  - --innodb-flush-log-at-trx-commit=2
  - --innodb-buffer-pool-size=2147483648
  - --innodb-io-capacity=200
  - --innodb-io-capacity-max=400
  - --innodb-max-dirty-pages-pct=10
```

On that hardware this took `POST /api/events` p99 from ~1 s to ~430 ms and the median to under 10 ms. The structural ceiling is still the disk: a local-NVMe data volume is the durable fix if ingest latency stays high after tuning.

## Why no WAF here

Agent telemetry legitimately contains attack signatures (captured command lines, file paths, malware and C2 activity), which a content-inspecting WAF flags as attacks and blocks. Caddy in this stack is a plain reverse proxy with no managed ruleset, so uploads to `POST /api/events` are never inspected for signatures. The authenticated agent channel is protected by its bearer token, which is the right control for machine-to-machine traffic. If you instead deploy behind a managed edge that runs a WAF, you must exempt the agent routes (`POST /api/events`, `POST /api/enroll`, `GET /api/commands`, `PUT /api/commands/*`) from inspection or agents will silently fail to upload.
