# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# FortiSafe (fortigate-scp-backup) — Go build
#
# SINGLE-PROCESS MODEL
#   The binary runs the HTTP server, the backup scheduler and every extension
#   background worker (e.g. the Graylog/HookWise VPN status monitor) as
#   goroutines inside ONE process. The old Python deployment had to pin
#   "gunicorn --workers 1" so the in-process APScheduler and the background
#   worker thread were not duplicated across workers; that constraint is GONE.
#   Just run a single container — no worker/thread tuning required.
#
# FULLY STATIC BINARY
#   CGO is disabled and the SQLite driver is the pure-Go modernc.org/sqlite,
#   so no libc is needed. The timezone database is embedded via `time/tzdata`
#   and all templates/static assets are embedded via Go `embed`. The runtime
#   image therefore only needs the binary plus CA certificates (for outbound
#   TLS to Graylog / HookWise / SMTP) — both provided by distroless/static.
# ---------------------------------------------------------------------------

# --- Stage 1: build ---------------------------------------------------------
FROM golang:1.27.0@sha256:4013ae0f9e7994f8535c58c811f8f863fbed38b72e0d51e6592156f758d66146 AS build

WORKDIR /src

# Download modules first so this layer is cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Build the fully static, stripped binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/fortisafe ./cmd/fortisafe \
    && install -d -m 0750 /out/backups \
    && install -d -m 0700 /out/data

# --- Stage 2: runtime -------------------------------------------------------
# The nonroot distroless variant includes CA certificates and has no shell or
# package manager, while immutable digests make rebuild inputs reproducible.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

WORKDIR /app

COPY --chown=65532:65532 --from=build /out/fortisafe /app/fortisafe
COPY --chown=65532:65532 --chmod=0750 --from=build /out/backups /app/backups
COPY --chown=65532:65532 --chmod=0700 --from=build /out/data /app/data

# Persistent data lives here. The binary creates these directories at startup
# via os.MkdirAll if they are missing (distroless has no shell, so we cannot
# `mkdir` at build time) — mount host volumes to persist:
#   /app/backups  -> backup files (BACKUP_DIR, default relative "backups")
#   /app/data     -> extension SQLite DB /app/data/fgt-adm-vpn-conf-db.db
# Declared as VOLUMEs so they are writable even when not explicitly mounted.
ENV DATA_DIR=/app/data
VOLUME ["/app/backups", "/app/data"]

USER 65532:65532

EXPOSE 8521

ENTRYPOINT ["/app/fortisafe"]
