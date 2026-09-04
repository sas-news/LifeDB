# Verification record

Date: 2026-09-01

## Completed locally

- Python source compilation.
- Six unit and integration tests.
- UUIDv7 generation and validation.
- Vault initialization.
- SHA-256 object deduplication.
- Sealed Evidence creation.
- Canon and Evidence validation.
- SQLite FTS index construction.
- Japanese bigram retrieval fallback.
- Complete deletion of `runtime/` followed by rebuild and successful search.
- HTTP health, ingest, rebuild, and Context Pack endpoints.
- JSON parsing of all supplied JSON Schemas.
- YAML parsing and structural checks of Compose and GitHub Actions files.

## Deferred to a Docker-capable host

The authoring environment did not contain a Docker executable, so the image and
Compose stack were not launched locally. `.github/workflows/ci.yml` contains a
Docker build and recovery smoke test. The first GitHub push or self-hosted
deployment must confirm this job before v0.1 is tagged.

## Release gate

Do not tag v0.1 until both CI jobs pass and a real host performs the recovery
drill in `docs/disaster-recovery.md`.
