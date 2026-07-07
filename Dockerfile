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
FROM golang:1.26 AS build

WORKDIR /src

# Download modules first so this layer is cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Build the fully static, stripped binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/fortisafe ./cmd/fortisafe

# --- Stage 2: runtime -------------------------------------------------------
# distroless/static ships CA certificates and runs as root by default, which we
# want so bind-mounted host volumes (/app/backups, /app/data) stay writable.
FROM gcr.io/distroless/static-debian12:latest

WORKDIR /app

COPY --from=build /out/fortisafe /app/fortisafe

# Persistent data lives here. The binary creates these directories at startup
# via os.MkdirAll if they are missing (distroless has no shell, so we cannot
# `mkdir` at build time) — mount host volumes to persist:
#   /app/backups  -> backup files (BACKUP_DIR, default relative "backups")
#   /app/data     -> extension SQLite DB /app/data/fgt-adm-vpn-conf-db.db
# Declared as VOLUMEs so they are writable even when not explicitly mounted.
ENV DATA_DIR=/app/data
VOLUME ["/app/backups", "/app/data"]

EXPOSE 8521

ENTRYPOINT ["/app/fortisafe"]
