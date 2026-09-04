# FortiSafe desktop UX rollout and rollback

This runbook releases only an immutable image digest that was built from the
same commit as every required quality gate. Browser evidence uses the synthetic
fixture or a new, empty staging database; never upload production screenshots,
traces, logs, configuration data, or credentials.

## Required controls

- Protect the GitHub `production` environment with required reviewers.
- Require the reusable CI jobs for formatting, build, vet, race tests, lint,
  Go vulnerability scanning, container scanning, deterministic rendering,
  Playwright, axe, and CSP before any image publication job can start.
- Keep publication workflow concurrency non-cancelling. A newer run waits for
  the current promotion instead of interrupting an alias update.
- Build and push the commit tag first. Test and deploy `IMAGE@sha256:...`; do
  not test or deploy a mutable tag.
- Record the candidate digest, commit, workflow URL, and the digest previously
  referenced by `latest` in the immutable publication artifact.
- Move `latest`, date, and release aliases only after the digest-pinned staging
  smoke succeeds and the protected production environment is approved.

## Staging gate

Use an ephemeral PostgreSQL database and synthetic credentials. Enable every
shipped extension, but point optional external integrations at an unreachable
local test endpoint so no third-party system is contacted.

The smoke gate must verify:

1. `GET /healthz` returns HTTP 200 and JSON status `ok`.
2. `GET /readyz` returns HTTP 200 and `ready`.
3. A new synthetic administrator can sign in.
4. The authenticated dashboard renders.
5. Every enabled extension returns HTTP 200, exposes its expected page heading,
   and marks exactly one navigation item current:
   - `/fgt-adm-vpn-conf/`
   - `/fgt-confgen/`
   - `/fgt-polsplit/`
   - `/fgt-confconv/`
   - `/fgt-conftail/`

Retain only the synthetic Playwright report, screenshots, and traces. Stop and
remove the staging container after every outcome.

## Publication-guard rehearsal

Before approving the first production rollout, dispatch the main workflow with
`force_quality_failure=true`.

Expected evidence:

- the intentional quality step fails;
- the candidate build, staging smoke, production approval, and alias promotion
  are skipped;
- `latest` still resolves to its previous digest;
- no release is created.

Repeat this rehearsal whenever the publication dependency graph changes.

## Production rollout

1. Download and verify the publication metadata artifact for the approved run.
2. Confirm its commit is the intended revision and its candidate digest is the
   digest that passed staging.
3. Record the `previous_digest` as the rollback target.
4. Approve the protected `production` environment.
5. Deploy the exact `IMAGE@DIGEST`, never `IMAGE:latest`.
6. Confirm `/healthz` and `/readyz` return HTTP 200 through the production path.
7. Sign in with a dedicated smoke account and visit the dashboard plus every
   extension enabled in production.
8. Verify application logs show the expected startup revision and no new
   authentication, CSP, template, database, Graylog, or Hookwise errors.
9. Record the deployment time, operator, digest, health evidence, and workflow
   URL in the change ticket.

## Rollback rehearsal and execution

Rehearse this procedure in staging before the first production approval:

1. Select the `previous_digest` from the candidate's publication metadata.
2. Confirm the digest exists in GHCR and belongs to the expected repository.
3. Deploy that immutable digest to staging.
4. Run the complete health, login, dashboard, and enabled-extension inventory.
5. Restore the candidate digest only after the rehearsal evidence is recorded.

For a production rollback, stop rollout traffic, deploy the recorded previous
digest, and repeat both explicit health checks and the production UI inventory.
Do not retag or deploy `latest` as a shortcut: its value can change independently
of the incident. Preserve the failed deployment's metadata and diagnostics, and
open a follow-up issue before attempting another promotion.

## Evidence checklist

- [ ] Quality workflow URL and gated commit
- [ ] Synthetic desktop browser artifact
- [ ] Candidate image digest artifact
- [ ] Synthetic staging smoke artifact
- [ ] Forced-failure guard rehearsal
- [ ] Protected-environment approval
- [ ] Production `/healthz` and `/readyz`
- [ ] Production page inventory
- [ ] Previous digest recorded
- [ ] Rollback rehearsal completed
