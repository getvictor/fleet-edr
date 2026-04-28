# syntax=docker/dockerfile:1.7

# Multi-stage build for the fleet-edr-server.
#
# Stage 1 (ui-build): Node builds the React UI. Vite's `outDir` is
# `../server/ui/dist` (see ui/vite.config.ts), so vite writes directly into
# the location `server/ui/embed.go`'s `//go:embed all:dist` expects.
#
# Stage 2 (build): Go compiles the server. The server binary is pure Go
# (go-sql-driver/mysql is CGo-free) so we can land on distroless/static
# in the final stage. VERSION and COMMIT build args become -ldflags for
# /livez + /readyz responses and observability resource attributes.
#
# Stage 3 (runtime): distroless/static-debian12:nonroot. CA bundles +
# tzdata + nonroot user, no shell, no package manager.
#
# Built for linux/amd64 and linux/arm64 via `docker buildx --platform`.

# ---------------------------------------------------------------
# Stage 1: UI bundle
# ---------------------------------------------------------------
# Image SHAs are pinned alongside the human-readable tag so OpenSSF Scorecard's
# Pinned-Dependencies check sees a digest. Refresh by running e.g.
# `docker manifest inspect node:20 --verbose` and copying the manifest digest.
# Dependabot's docker ecosystem keeps these current; do not strip the digest
# during a tag bump.
FROM --platform=$BUILDPLATFORM node:20@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5 AS ui-build
# package*.json first for layer-cache reuse: npm ci only reruns when
# dependencies change, not every source edit.
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --ignore-scripts
# Vite writes to `../server/ui/dist` (relative to /src/ui) = /src/server/ui/dist.
# Pre-create that parent so vite can emptyOutDir without tripping on EACCES.
RUN mkdir -p /src/server/ui
COPY ui ./
RUN npm run build
# Output: /src/server/ui/dist/{index.html,assets/...}

# ---------------------------------------------------------------
# Stage 2: Go binary
# ---------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:b54cbf583d390341599d7bcbc062425c081105cc5ef6d170ced98ef9d047c716 AS build
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
# Drop in the UI bundle from stage 1 so //go:embed all:dist finds content.
COPY --from=ui-build /src/server/ui/dist ./server/ui/dist

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILDTIME}" \
        -o /out/fleet-edr-server \
        ./server/cmd/fleet-edr-server

# ---------------------------------------------------------------
# Stage 3: runtime
# ---------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1

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
