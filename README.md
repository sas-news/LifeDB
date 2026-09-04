# LifeDB

LifeDB is a local-first, agent-neutral, recoverable memory substrate for a
person. Canon is the owner's accepted current model. Evidence records what was
observed or captured; it is not labeled as truth. Databases, embeddings,
containers, effective views, and Context Packs are disposable projections.

This repository is the LifeDB v0.2 executable specification and reference
implementation. The Canon bundle targets OKF v0.2 while adding path-independent
UUIDv7 identity and typed Claim provenance under `x-lifedb`.
The compatibility reference is the [OKF v0.2 specification](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md).

## The four stores

| Store | Purpose | Authority | Deletable |
| --- | --- | --- | --- |
| `canon/` | Accepted current semantic model | Current semantic state | Only by an exact owner-authorized operation |
| `evidence/` | Immutable captures and append-only events | What LifeDB recorded and its lifecycle | Normally append-only; owner erasure is the exception |
| `objects/` | Raw, represented, and Canon snapshot bytes | Byte identity while present | Policy- and dependency-dependent |
| `runtime/` | SQLite index, effective views, caches, Context Packs | Never authoritative | Always |

Current payload availability and representations are projected from a sealed
capture plus ordered immutable lifecycle events. A payload can be evicted while
the observation envelope remains. SHA-256 detects byte changes and enables
deduplication; it does not authenticate a source or prove a statement.

## What the v0.2 reference implements

- UUIDv7 vault and semantic identities;
- atomic, integrity-bearing Evidence capture records using schema 0.2;
- source-scoped `external_id` idempotency (the key is
  `(source.kind, source.uri, source.account, source.device, source.external_id)`;
  legacy `source.metadata.account`/`device` values are promoted into the source
  envelope);
- SHA-256 Object Store deduplication;
- `reference-only` capture that requires a URI and never stores original bytes;
- a vault-global append-only event sequence with `previous_event` linkage;
- effective Evidence projection for representations and payload lifecycle;
- typed Claim Evidence requirements: `raw`, `representation:<role>`, and
  `record-only`;
- explicit manual Candidate creation, inspection, rejection, and promotion;
- prepared/committed Canon snapshot transactions and compensating rollback;
- Canon and Evidence validation and disposable lexical index rebuild;
- SQLite projections for `concepts`, `claims`, `claim_evidence`, and
  `claim_edges` (graph-shaped data is materialized, but no graph query or
  ranking API is exposed);
- dirty-index and durable/indexed sequence watermarks;
- character-budgeted Context Packs with Core, heuristic Continuity, lexical
  Relevant retrieval, and untrusted-content delimiters;
- explicit retention preview, exact-confirmation apply, and interrupted-apply
  recovery for eligible raw payloads (manual CLI operations only);
- Bearer authentication and a server-side sensitivity ceiling for HTTP;
- server-side sensitivity ceiling/floor enforcement and policy-bounded Context
  budgets;
- Docker bind-mount deployment and runtime-deletion recovery tests.

The executable boundaries are intentionally finite: HTTP and CLI raw input are
limited to 64 MiB, durable records to 16 MiB, Canon and indexed text to 8 MiB,
Context and Evidence expansion to 1,000,000 characters, search queries to 4,096
characters, and search results to 100. Frontmatter, mappings, policies, and
source metadata are each limited to 1 MiB; event data is limited to 4 MiB.
These are resource ceilings, not promises of throughput. Event append and
source-idempotency lookup are O(N) over the durable record set and the v0.2
reference uses a single durable writer.

## Deliberately not implemented

The current reference software does not implement:

- automatic AI extraction, Candidate creation, promotion, or background
  reconciliation;
- automatic object eviction or any scheduled retention apply;
- owner-authorized erasure preview/apply;
- universal automatic agent preflight/postflight hooks;
- MCP;
- vector, graph-ranked, embedding, or learned-reranking search;
- browser, mail, calendar, ActivityWatch, screenshot, audio, or other external
  collectors;
- OCR, captioning, transcription, or other representation generators;
- multi-writer or multi-device synchronization;
- application-level object encryption or digital signatures.

Ordinary retention can delete only raw Object Store bytes selected by an exact,
persisted preview. It does not erase the sealed Evidence envelope and is never
scheduled automatically. Owner erasure is specified but not implemented.
Encrypted host storage and encrypted backups remain deployment responsibilities.
An installation must not claim unimplemented capabilities merely because the
durable format reserves them.

## Quick start with the CLI

Install into an isolated Python environment, then keep the real vault outside the
source repository:

```sh
python -m pip install .
export LIFEDB_VAULT=/absolute/path/to/lifedb-vault
lifedb init
printf '%s' 'LifeDB remains reconstructable from durable files.' \
  | lifedb ingest - --media-type text/plain --filename memory.txt
lifedb validate
lifedb rebuild
lifedb context 'What must remain reconstructable?' --markdown
```

CLI calls run as the current operating-system user and do not pass through the
HTTP authentication layer. Protect the vault with filesystem permissions and
encrypted storage.

Useful explicit workflows are:

```sh
# Associate recent conversation Evidence with Continuity routing labels.
printf '%s' 'Continue the migration after validation.' \
  | lifedb ingest - --media-type text/plain --kind conversation \
      --source-metadata '{"session":"session-42","workspace":"/srv/project"}'
lifedb context 'What remains open?' --session session-42 \
  --workspace /srv/project --markdown

# Create an immutable representation event.
lifedb evidence add-representation 019d0000-0000-7000-8000-000000000001 ocr.txt \
  --role ocr --media-type text/plain --actor process:ocr \
  --producer-version 1.0

# Preview eligible raw-payload eviction. Copy the returned id and confirmation
# exactly; apply revalidates the plan and fails if durable state changed.
lifedb retention preview
lifedb retention apply 019d0000-0000-7000-8000-000000000002 \
  --confirm 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  --actor owner:local
lifedb retention recover
```

The UUIDs and digest above are placeholders. A fresh vault defaults manual
ingest to `durable`, which is intentionally excluded from ordinary eviction;
only policy-eligible `grace` or `derivative-only` captures can appear as
candidates.

## Docker

```sh
cp .env.example .env
mkdir -p ./vault
docker compose run --rm lifedb init
docker compose up -d --build lifedb
curl http://127.0.0.1:7331/health
```

The default deployment bind-mounts the host vault and publishes only on
localhost. Set `LIFEDB_VAULT` to an absolute backed-up host path for real data.
Do not use an anonymous Docker volume as the only durable copy.

## Authenticated HTTP

Set a strong `LIFEDB_API_TOKEN` in the service environment or an external secret
mechanism. Do not put it in the vault or commit it. Every `/v1/*` request
requires the Bearer token; only `/health` is unauthenticated.

`LIFEDB_SENSITIVITY_CEILING` sets the server maximum and defaults to
`personal`. A request can ask for a lower ceiling but cannot raise it.
`LIFEDB_INGEST_SENSITIVITY_FLOOR` sets the minimum label applied to HTTP
captures; callers may raise a label but cannot lower it. Context budgets are
also bounded by the validated durable context policy.

```sh
curl -X POST http://127.0.0.1:7331/v1/context \
  -H "Authorization: Bearer ${LIFEDB_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "What are the storage invariants?",
    "budget_chars": 12000,
    "core_chars": 4000,
    "continuity_chars": 2000,
    "relevant_chars": 6000
  }'
```

The server clamps requested sensitivity and character budgets to its own
profile. Context output reports
`{durable_sequence, indexed_sequence, dirty}` and encloses retrieved memory in
escaped untrusted-data delimiters.

Localhost is not an authorization boundary by itself. The reference server has
one Bearer owner token and does not split operation scopes within that token.
Remote exposure additionally requires TLS, a reverse proxy, destination policy,
rate and quota controls, free-space monitoring, and an explicit security review.
The reference does not enforce per-source quotas, request rates, or free-space
thresholds.

## Claims and retained support

A v0.2 Claim names the minimum Evidence material it needs:

```yaml
evidence:
  - id: 019d1255-7d6a-7e43-92bd-0f137f516006
    requires: raw
  - id: 019d1255-7d6a-7e43-92bd-0f137f516007
    requires: representation:ocr
  - id: 019d1255-7d6a-7e43-92bd-0f137f516008
    requires: record-only
```

A bare v0.1 Evidence UUID is conservatively read as `raw`. New v0.2 writes use
the explicit mapping. A Canon citation therefore does not automatically pin
every raw web or passive-capture payload, while a real raw dependency cannot be
silently evicted.

## Manual Candidate workflow

Ingestion creates Evidence, never Canon. A manual Candidate proposes a validated
Claim for a target Canon document. Explicit promotion verifies semantic and
Evidence references, sensitivity, validity, and supersession before writing
Canon through:

1. durable before/after snapshots;
2. `canon.change-prepared`;
3. atomic compare-and-swap publication;
4. `canon.change-committed`.

Failure restores the before snapshot and records an aborted transaction.
Rollback verifies current bytes and creates
`canon.rollback-prepared/committed`; it does not erase the original history.
There is no automatic AI promotion in v0.2.

## Recovery invariant

Deleting `runtime/` must never delete accepted knowledge or observation history.
Stop the LifeDB server first, then use the guarded command against the exact
initialized vault (the command refuses broad, symlinked, or uninitialized
targets):

```sh
docker compose down
docker compose run --rm lifedb runtime reset --confirm DELETE-RUNTIME
docker compose run --rm lifedb rebuild
docker compose run --rm lifedb validate
```

Run this only after resolving the exact configured vault path. Recovery verifies
Capture and Event integrity, event ordering, retained Objects, Canon snapshots,
typed Evidence requirements, and the rebuilt watermark.

The durable backup set is `vault.json`, `canon/`, `evidence/`, `objects/`,
`policies/`, `schemas/`, and `migrations/`. Include `quarantine/` whenever a
retention transaction is prepared or in flight; otherwise it is staging rather
than an authoritative store. `runtime/` is disposable and need not be backed
up. Backups must be consistent at a declared durable sequence. Git alone is
not a LifeDB backup.

## Personal data and owner erasure

A real vault should use encrypted host storage, encrypted off-site backups,
restricted filesystem permissions, and separate key custody. Do not commit the
vault, authentication tokens, passwords, private keys, or credentials.

Normal records are append-only, but owner-authorized erasure takes priority.
The design requires a complete preview and exact confirmation across captures,
events, objects, representations, Canon snapshots, and runtime copies. LifeDB
cannot delete offline or provider-managed backups itself; inventory, expiry, and
preventing restoration of erased data belong to the deployment operator.

The v0.2 reference does not implement owner-erasure preview or apply. Do not use
ordinary `lifedb retention apply` as a substitute: it removes only eligible raw
payload objects and deliberately preserves Capture and Event history.

## Documents

- [Durable format and Canon specification](SPEC.md)
- [Philosophy and v0.2 boundary](docs/philosophy.md)
- [Threat model](docs/threat-model.md)
- [Context protocol](docs/context-protocol.md)
- [Retention policy](docs/retention.md)
- [Disaster recovery](docs/disaster-recovery.md)
- [Verification record](docs/verification.md) (legacy v0.1 checklist; not a v0.2 release-gate report)
- [ADR 0001: durable files and disposable runtime](docs/decisions/0001-durable-files-disposable-runtime.md)
- [ADR 0002: append-only lifecycle events and Canon transactions](docs/decisions/0002-append-only-lifecycle-events.md)

## Conformance status

Version 0.2 narrows the executable core to durable capture/events, explicit
manual Canon changes, authorized lexical Context, and recovery. The repository's
tests are evidence for the paths they exercise, not a claim that external
Docker, backup, TLS, model-provider, or future collector behavior has been
verified.

MCP, vectors, graph-ranked retrieval, collectors, representation generation, automatic
preflight/postflight integration, and automatic AI reconciliation are explicitly
outside v0.2 conformance.
