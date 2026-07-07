# Contributing

Thanks for helping improve FortiSafe. This project is a single Go module.

## Prerequisites

- Go 1.26+
- Docker (for building the image and running an integration Postgres)

## Development loop

```bash
go build ./...          # compile everything
go vet ./...            # static checks
go test ./...           # unit tests (fast, no external services)
gofmt -w cmd internal extensions
golangci-lint run       # lint (config in .golangci.yml)
```

Run the app locally against a throwaway Postgres:

```bash
docker run -d --name fs-db -e POSTGRES_USER=postgre -e POSTGRES_PASSWORD=pass \
  -e POSTGRES_DB=firewall_backups -p 15432:5432 postgres:16

PG_HOST=localhost PG_PORT=15432 PG_USER=postgre PG_PASSWORD=pass \
  PG_DATABASE=firewall_backups BACKUP_DIR=./backups DATA_DIR=./data \
  go run ./cmd/fortisafe
# open http://localhost:8521  (admin / changeme)
```

## Tests

- Unit tests run with the default `go test ./...` and require nothing external.
- The store integration test is **skipped** unless `TEST_PG_HOST` is set:

  ```bash
  TEST_PG_HOST=localhost TEST_PG_PORT=15432 TEST_PG_USER=postgre \
    TEST_PG_PASSWORD=pass TEST_PG_DATABASE=firewall_backups \
    go test ./internal/database
  ```

- Run the fuzzers with e.g. `go test ./internal/web -fuzz FuzzBuildSearchPattern`.

## Conventions

- Keep `gofmt`/`goimports` clean and `golangci-lint` green — CI enforces both.
- Match the surrounding code's style, comment density, and naming.
- Database changes go through `internal/database/migrations.go` as a new,
  idempotent, ordered migration — never edit an already-released migration.
- New feature modules follow [docs/EXTENSIONS.md](docs/EXTENSIONS.md).
- Preserve drop-in database compatibility unless a change is an explicit,
  documented forward migration.

## Pull requests

1. Branch off `main`.
2. Ensure build, vet, test, and lint pass locally.
3. Open a PR; CI runs build/vet/test(race)/lint and `govulncheck`.

Releases are cut by pushing a `vX.Y.Z` tag, which builds a multi-arch image and
creates a GitHub release (see `.github/workflows/release.yml`).
