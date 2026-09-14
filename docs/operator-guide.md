# LifeDB operator guide

This is the authoritative operating guide for the local LifeDB service and its optional OpenCode and Hermes adapters. It describes the current implementation, not Task 17 deployment. Run commands only after setting the declared temporary variables below.

## Compatibility and safety

Use Python 3.11 or newer, the repository `.venv` managed by `uv`, Docker Compose, OpenCode 1.18.29, and Hermes 0.21.0, release tag `v2026.8.31`. OpenCode uses `~/.config/opencode/opencode.json` and `~/.config/opencode/plugins/`. Hermes uses its explicit `--hermes-home` tree. Never run this guide against a real home, vault, token, provider credential, or production Compose project.

The service has one unscoped owner token. Same UID users and administrators can read local files. Workspace paths, session labels, prompts, and retained text can be durable metadata. Logs exclude credentials and payloads where the implementation specifies, but credential detection is not general DLP. Localhost is not authorization. There is no application encryption, remote TLS, throughput, cross-platform, or backup-provider guarantee.

| Area | Current contract |
| --- | --- |
| Prerequisites | Python 3.11+, `.venv` from `uv`, Docker Compose, OpenCode 1.18.29, Hermes 0.21.0 (`v2026.8.31`) |
| XDG ownership | OpenCode `~/.config/opencode/opencode.json` and `plugins/`; Hermes uses `$HERMES_HOME`; all smoke paths are temporary |
| Service status | `/health` is unauthenticated `200`; protected requests are `401` without valid auth, `503` when auth is unconfigured |
| HTTP outcomes | turns: `201` create/replay, `409` changed replay, `422` credential rejection; context reports `dirty`, `indexed_sequence`, `durable_sequence` |
| Limits | raw input 64 MiB, turn body 2 MiB, query 4096 chars, search 100 results, Context/Evidence expansion 1,000,000 chars |

| Context profile | Total | Core | Continuity | Relevant |
| --- | ---: | ---: | ---: | ---: |
| Server durable defaults | 24000 | 8000 | 4000 | 12000 |
| Adapter defaults | 12000 | 4000 | 2000 | 6000 |

| OpenCode setting | Environment key | Default / bound |
| --- | --- | --- |
| Service URL | `LIFEDB_SERVICE_URL` | loopback `http://127.0.0.1:7331` |
| Timeout | `LIFEDB_OPENCODE_TIMEOUT_MS` | implementation default; max 120000 ms |
| Response bytes | `LIFEDB_OPENCODE_MAX_RESPONSE_BYTES` | implementation default; max 4194304 |
| Workspace and sensitivity | `LIFEDB_OPENCODE_WORKSPACE`, `LIFEDB_OPENCODE_SENSITIVITY` | unset unless selected |
| Context budgets | `LIFEDB_OPENCODE_BUDGET_CHARS`, `_CORE_CHARS`, `_CONTINUITY_CHARS`, `_RELEVANT_CHARS` | adapter defaults; each max 1000000 |
| Result limit | `LIFEDB_OPENCODE_LIMIT` | adapter default; max 100 |

| Hermes setting | CLI key | Default / bound |
| --- | --- | --- |
| Endpoint and workspace | `--url`, `--workspace` | loopback URL; unset workspace |
| Transport limits | `--timeout-seconds`, `--max-response-bytes`, `--max-request-bytes` | 2.0, 1048576, 4194304 |
| Context budgets | `--budget-chars`, `--core-chars`, `--continuity-chars`, `--relevant-chars` | 12000, 4000, 2000, 6000; max 1000000 |
| Results and sensitivity | `--limit`, `--sensitivity-ceiling` | 8; policy-bounded |

## Temporary smoke path

The documentation validator extracts typed `sh`, `shell`, and `bash` fences, checks links without network access, rejects unknown command IDs, placeholders, and undeclared variables, and executes only the scenario wrappers in a temporary directory. Operator command fences are extracted into non-invoked shell functions and checked with Bash syntax. It never evaluates an operator command. A token must be generated into a mode `0600` file and must never be printed.

<!-- smoke: scenario=bootstrap expect=ok -->
```sh
PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py --scenario bootstrap
```

The smoke environment uses `$SMOKE_ROOT`, `$PROJECT`, `$HERMES_HOME`, `$TOKEN_FILE`, `$LIFEDB_API_TOKEN_FILE`, `$TOKEN`, `$PORT`, `$QUERY`, `$CONFLICT_TURN_JSON`, and `$CREDENTIAL_TURN_JSON`; these are shell variables, not literal paths. The default gate validates all command declarations and executes every non-Docker scenario once. Use `--with-docker` or `--scenario compose` for the explicit Compose deployment.

## Vault and token bootstrap

For a real deployment, choose an absolute XDG data path outside this repository, create the vault only if absent, and validate it rather than replacing it. Create the token atomically only if absent, require owner-only mode `0600`, and reject symlinks, whitespace, short values, and changed existing contents. The Compose wrapper requires an absolute existing non-symlink vault and the exact token mode. `LIFEDB_VAULT`, `LIFEDB_API_TOKEN`, `LIFEDB_SENSITIVITY_CEILING`, and `LIFEDB_INGEST_SENSITIVITY_FLOOR` are non-secret deployment settings except for the token value. Do not put token content in `.env`, logs, evidence, or Git.

Use only `scripts/lifedb-compose.py`. It owns the repository `compose.yaml` and project directory, accepts unique `-p` project names, and rejects raw override channels such as `-f`, `--env-file`, `--project-directory`, `COMPOSE_FILE`, and `COMPOSE_ENV_FILES`. It runs as the current non-root UID and GID. The service binds loopback only, uses a read-only token mount, a read-only filesystem, dropped capabilities, and no-new-privileges. The vault mount is writable because it is the durable store. Compose commands are `up -d`, `down`, `run --rm`, and `ps`.

Use the Compose command fences below with `PROJECT`, `LIFEDB_VAULT`, `LIFEDB_API_TOKEN_FILE`, and `PORT` set to isolated values. Export `LIFEDB_API_TOKEN_FILE` for the wrapper. The check-only form is the `compose-config` fence.

## Health and HTTP contract

`GET /health` returns `200` without auth. Protected routes return `401` for missing or wrong auth and `503` when auth is unconfigured. `POST /v1/turns` returns `201` for a new turn and replay, `409` for a conflicting replay, and `422` for rejected credentials without Evidence or Object growth. `/v1/context` returns the watermark fields `dirty`, `indexed_sequence`, and `durable_sequence`. `Cache-Control: no-store` applies to sensitive responses. Turn bodies are limited to 2 MiB and the general raw boundary to 64 MiB. Do not invent `/status` or `/conformance` routes.

The durable Context defaults are `24000`, `8000`, `4000`, and `12000` characters for total, core, continuity, and relevant content. Adapter defaults are smaller: `12000`, `4000`, `2000`, and `6000`. Keep these sets distinct.

The documented probes are the `http-health`, `http-missing-auth`, `http-wrong-auth`, `http-context`, and `http-turn` fences. Reuse `TURN_JSON` for replay, change only its turn body for conflict, and use a separate non-secret credential fixture for rejection.

## CLI inspection and recovery

Use `lifedb --vault <vault> evidence show <id>`, `lifedb --vault <vault> search <query>`, `lifedb --vault <vault> context <query>`, `lifedb --vault <vault> doctor`, `lifedb --vault <vault> rebuild`, and `lifedb --vault <vault> validate` through the approved wrapper or an explicitly selected temporary vault. A clean watermark is `dirty=false` and `indexed_sequence=durable_sequence`. Back up `vault.json`, `canon/`, `evidence/`, `objects/`, `policies/`, `schemas/`, `migrations/`, and active `quarantine/`; runtime, indexes, caches, and Context Packs are disposable.

The temporary CLI sequence is the `cli-evidence`, `cli-search`, `cli-context`, `cli-doctor`, `cli-rebuild`, and `cli-validate` fence set. The wrapper recovery sequence is represented by the Compose fences `compose-stop`, `compose-runtime-reset`, `compose-rebuild`, `compose-validate`, `compose-search`, and `compose-doctor`.

Runtime deletion is not Canon rollback, raw retention, Evidence retention, or owner erasure. Stop the service before deleting only `runtime/`, then rebuild and validate. `lifedb retention recover` handles an interrupted retention transaction. Canon rollback is compensating history, preserving both original and rollback events. Owner erasure is not implemented. Never apply retention with invented IDs.

<!-- smoke: scenario=runtime expect=200,201,401,409,422,clean -->
```sh
PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py --scenario runtime
```

## OpenCode adapter

From `integrations/opencode`, use the OpenCode command fences. Check and install require OpenCode 1.18.29. The owned files are `lifedb.ts` and `lifedb.ts.disabled` under the XDG global plugin directory. Disable, enable, uninstall, and reinstall affect only those files and preserve unrelated plugins. Runtime settings are non-secret URL, token-file path, budgets, and bounds. Injection is transient. There is no spool or retry queue, so a service outage or rejection can permanently lose a turn. A clean idle capture contains the user and final assistant pair, not Context Pack, reasoning, tool, or synthetic content.

Inspect with the `opencode-debug-config` fence and use the `opencode-run-json` fence only in a temporary XDG home. The settings are listed in the settings table below.

<!-- smoke: scenario=adapters expect=ok -->
```sh
# OpenCode argv: bun run src/installer/cli.ts check|install|disable|enable|uninstall
# Hermes argv: PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home "$HERMES_HOME" check|install|disable|enable|uninstall
PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py --scenario adapters
```

## Hermes adapter

Invoke the repository-root installer with explicit `--hermes-home`. Stop Hermes and prevent concurrent same-UID mutation of its home for the entire installer lifecycle. Hermes 0.21.0 `check` invokes the host diagnostic command `hermes plugins doctor <plugin-path> --ci` through its exact six-line protocol; `doctor` is not an installer subcommand. Lifecycle operations use the installer lock `.lifedb-installer.lock`, transaction journal `.lifedb-transaction.json`, journal store `.lifedb-journal-store/`, temporary staging/quarantine trees, and `.lifedb-backups/`; the lock, journal, store, staging, and quarantine artifacts are transient and successful operations clear them, while owned backups may remain for rollback. Check, install, disable, enable, uninstall, and reinstall touch only the owned tree, config, and these installer artifacts. A real Hermes import may create one optional immediate `__pycache__` directory containing only validated CPython 3.11+ cache names for installed `.py` modules; this reserved empty cache directory may be removed, and its mutable disposable files are excluded from marker/source hashes and removed automatically with the owned root during replacement or uninstall. Operators must not manually pre-clean caches. Unexpected cache names, nested entries, symlinks, non-regular files, owners, or writable group/other modes fail closed and preserve bytes and recoverable journal state. Python 3.11 cannot portably prevent a malicious same-UID swap after the final identity check; the stopped-host/same-UID boundary is required and is not an absolute race guarantee. Settings preserve the adapter budgets and bounds. Exactly three hooks are installed: `pre_llm_call`, `post_llm_call`, and `on_session_end`; `on_session_end` authorizes capture. State is bounded in memory, has no spool, and preserves unrelated LanceDB data. Evidence remains retained when the adapter is removed.

The Hermes lifecycle and reinstall syntax are the Hermes command fences below. Wrong versions, unsafe token files, stopped service, and missing token-file checks must fail closed without modifying unrelated files.

## Machine command manifest

Set `SMOKE_ROOT`, `PROJECT`, `HERMES_HOME`, `TOKEN_FILE`, `LIFEDB_API_TOKEN_FILE`, `PORT`, `QUERY`, `EVIDENCE_ID`, `TURN_JSON`, `CONFLICT_TURN_JSON`, `CREDENTIAL_TURN_JSON`, `LIFEDB_VAULT`, and a non-secret `WRONG_TOKEN` fixture before using these copyable commands. Export `LIFEDB_API_TOKEN_FILE` before running the Compose fences. OpenCode fences run from `integrations/opencode`; Hermes fences run from the repository root.

<!-- smoke: command=bootstrap-check owner=bootstrap -->
```sh
PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py --scenario bootstrap
```

<!-- smoke: command=compose-config owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" config --quiet
```
<!-- smoke: command=compose-init owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" run --rm lifedb init
```
<!-- smoke: command=compose-up owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" up -d --build lifedb
```
<!-- smoke: command=compose-ps owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" ps
```
<!-- smoke: command=compose-health owner=compose -->
```sh
curl http://127.0.0.1:$PORT/health
```
<!-- smoke: command=compose-context owner=compose -->
```sh
printf 'url = http://127.0.0.1:%s/v1/context\nheader = Authorization: Bearer %s\nrequest = POST\n' "$PORT" "$(<"$LIFEDB_API_TOKEN_FILE")" | curl --config - --data '{}'
```
<!-- smoke: command=compose-validate owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" run --rm lifedb validate
```
<!-- smoke: command=compose-stop owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" stop lifedb
```
<!-- smoke: command=compose-runtime-reset owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" run --rm lifedb runtime reset --confirm DELETE-RUNTIME
```
<!-- smoke: command=compose-rebuild owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" run --rm lifedb rebuild
```
<!-- smoke: command=compose-search owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" run --rm lifedb search "$QUERY"
```
<!-- smoke: command=compose-doctor owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" run --rm lifedb doctor
```
<!-- smoke: command=compose-down owner=compose -->
```sh
PYTHONPATH=src .venv/bin/python scripts/lifedb-compose.py -p "$PROJECT" down
```
<!-- smoke: command=http-health owner=runtime -->
```sh
curl http://127.0.0.1:$PORT/health
```
<!-- smoke: command=http-missing-auth owner=failure -->
```sh
curl -i -X POST http://127.0.0.1:$PORT/v1/context --data '{}'
```
<!-- smoke: command=http-wrong-auth owner=failure -->
```sh
printf 'url = http://127.0.0.1:%s/v1/context\nheader = Authorization: Bearer %s\nrequest = POST\n' "$PORT" "$WRONG_TOKEN" | curl --config - --data '{}'
```
<!-- smoke: command=http-context owner=runtime -->
```sh
printf 'url = http://127.0.0.1:%s/v1/context\nheader = Authorization: Bearer %s\nrequest = POST\n' "$PORT" "$(<"$TOKEN_FILE")" | curl --config - --data '{}'
```
<!-- smoke: command=http-turn owner=runtime -->
```sh
printf 'url = http://127.0.0.1:%s/v1/turns\nheader = Authorization: Bearer %s\nrequest = POST\n' "$PORT" "$(<"$TOKEN_FILE")" | curl --config - --data-binary @"$TURN_JSON"
```
<!-- smoke: command=http-replay owner=runtime -->
```sh
printf 'url = http://127.0.0.1:%s/v1/turns\nheader = Authorization: Bearer %s\nrequest = POST\n' "$PORT" "$(<"$TOKEN_FILE")" | curl --config - --data-binary @"$TURN_JSON"
```
<!-- smoke: command=http-conflict owner=runtime -->
```sh
printf 'url = http://127.0.0.1:%s/v1/turns\nheader = Authorization: Bearer %s\nrequest = POST\n' "$PORT" "$(<"$TOKEN_FILE")" | curl --config - --data-binary @"$CONFLICT_TURN_JSON"
```
<!-- smoke: command=http-credential-reject owner=failure -->
```sh
printf 'url = http://127.0.0.1:%s/v1/turns\nheader = Authorization: Bearer %s\nrequest = POST\n' "$PORT" "$(<"$TOKEN_FILE")" | curl --config - --data-binary @"$CREDENTIAL_TURN_JSON"
```
<!-- smoke: command=cli-evidence owner=runtime -->
```sh
PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault "$LIFEDB_VAULT" evidence show "$EVIDENCE_ID"
```
<!-- smoke: command=cli-search owner=runtime -->
```sh
PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault "$LIFEDB_VAULT" search "$QUERY"
```
<!-- smoke: command=cli-context owner=runtime -->
```sh
PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault "$LIFEDB_VAULT" context "$QUERY"
```
<!-- smoke: command=cli-doctor owner=runtime -->
```sh
PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault "$LIFEDB_VAULT" doctor
```
<!-- smoke: command=cli-rebuild owner=runtime -->
```sh
PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault "$LIFEDB_VAULT" rebuild
```
<!-- smoke: command=cli-validate owner=runtime -->
```sh
PYTHONPATH=src .venv/bin/python -m lifedb.cli --vault "$LIFEDB_VAULT" validate
```
<!-- smoke: command=opencode-check owner=adapters -->
```sh
bun run src/installer/cli.ts check
```
<!-- smoke: command=opencode-install owner=adapters -->
```sh
bun run src/installer/cli.ts install
```
<!-- smoke: command=opencode-disable owner=adapters -->
```sh
bun run src/installer/cli.ts disable
```
<!-- smoke: command=opencode-enable owner=adapters -->
```sh
bun run src/installer/cli.ts enable
```
<!-- smoke: command=opencode-uninstall owner=adapters -->
```sh
bun run src/installer/cli.ts uninstall
```
<!-- smoke: command=opencode-reinstall owner=adapters -->
```sh
bun run src/installer/cli.ts uninstall && bun run src/installer/cli.ts install
```
<!-- smoke: command=opencode-debug-config owner=adapters -->
```sh
opencode debug config
```
<!-- smoke: command=opencode-run-json owner=adapters -->
```sh
opencode run --format json
```
<!-- smoke: command=hermes-check owner=adapters -->
```sh
PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home "$HERMES_HOME" check
```
<!-- smoke: command=hermes-install owner=adapters -->
```sh
PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home "$HERMES_HOME" install --token-file "$TOKEN_FILE"
```
<!-- smoke: command=hermes-disable owner=adapters -->
```sh
PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home "$HERMES_HOME" disable
```
<!-- smoke: command=hermes-enable owner=adapters -->
```sh
PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home "$HERMES_HOME" enable
```
<!-- smoke: command=hermes-uninstall owner=adapters -->
```sh
PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home "$HERMES_HOME" uninstall
```
<!-- smoke: command=hermes-reinstall owner=adapters -->
```sh
PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home "$HERMES_HOME" uninstall && PYTHONPATH=. .venv/bin/python -m integrations.hermes.installer.cli --hermes-home "$HERMES_HOME" install --token-file "$TOKEN_FILE"
```

## Conformance and upgrades

Full automatic conformance is conditional. It applies only while LifeDB is healthy, the host versions are compatible, enabled hooks and token work, and each turn completes its preflight and postflight pair. Outage, disablement, incompatible versions, missing hook pairs, restart, or rejection is not Full and may lose turns. There is no generic migration command, model-provider guarantee, scoped token, encryption claim, or owner-erasure command.

Before upgrades, back up durable state, record versions, run check commands, disable the adapter if required, install the tested version, and run validation. To roll back, restore the owned adapter backup or uninstall and reinstall the known-good version, then run LifeDB rebuild, validate, and search. Do not begin Task 17 real deployment from this guide.

<!-- smoke: scenario=compose expect=config,init,health,hardening,recovery,cleanup -->
```sh
PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py --scenario compose
```

<!-- smoke: scenario=failure expect=401,409,503 -->
```sh
PYTHONPATH=src .venv/bin/python scripts/docs-smoke.py --scenario failure
```

## Related policy documents

- [Context protocol](context-protocol.md)
- [Retention policy](retention.md)
- [Disaster recovery](disaster-recovery.md)
- [Threat model](threat-model.md)
- [Verification record](verification.md)
