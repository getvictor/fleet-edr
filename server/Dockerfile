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

# Go workspace: the server module depends on the internal/envparse shared
# module via go.work. Copy the full tree; dependencies are small and the
# Docker layer cache keeps mod downloads fast across builds.
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
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
