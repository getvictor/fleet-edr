# syntax=docker/dockerfile:1.7

# Multi-stage build for the fleet-edr-server. The binary is pure Go (the
# MySQL driver is go-sql-driver/mysql, no cgo) so the final image can live on
# distroless/static. Build args VERSION and COMMIT become -ldflags for the
# /livez + /readyz responses and for observability resource attributes.
#
# Built for linux/amd64 and linux/arm64 via `docker buildx --platform`.

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILDTIME=

WORKDIR /src

# Explicit copies rather than `COPY . .` so the build context only ever
# contains what the server binary actually needs. The .dockerignore already
# excludes secrets and scratch dirs, but enumerating sources here bounds
# the image from a Dockerfile-only read (defense in depth) and satisfies
# the "recursively copying context directories" scanner rule.
#
# Server binary dependencies:
#   go.mod + go.sum  — module graph
#   server/          — the server code + embedded UI assets
#   internal/        — shared helpers (envparse, observability) referenced
#                      by both server and agent packages in the monorepo
COPY go.mod go.sum ./
COPY server ./server
COPY internal ./internal

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILDTIME}" \
        -o /out/fleet-edr-server \
        ./server/cmd/fleet-edr-server

# distroless/static gives us CA bundles + tzdata + nonroot user without a
# shell or package manager. The server opens no local files beyond TLS certs
# and makes outbound MySQL + OTLP connections; nothing needs glibc.
FROM gcr.io/distroless/static-debian12:nonroot

# Non-secret defaults. Operators override via compose env or EDR_*_FILE mounts.
ENV EDR_LISTEN_ADDR=":8088" \
    EDR_LOG_FORMAT="json" \
    EDR_LOG_LEVEL="info"

COPY --from=build /out/fleet-edr-server /usr/local/bin/fleet-edr-server

USER nonroot:nonroot
EXPOSE 8088

# No HEALTHCHECK here — compose-level healthcheck hitting /readyz owns that so
# the whole stack can key on it. Keeping the image shell-less means a curl-
# based HEALTHCHECK would need a static binary copy anyway.
ENTRYPOINT ["/usr/local/bin/fleet-edr-server"]
